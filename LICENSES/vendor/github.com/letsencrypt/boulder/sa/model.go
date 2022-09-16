package sa

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"time"

	jose "gopkg.in/square/go-jose.v2"

	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/db"
	"github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/probs"
	"github.com/letsencrypt/boulder/revocation"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

// errBadJSON is an error type returned when a json.Unmarshal performed by the
// SA fails. It includes both the Unmarshal error and the original JSON data in
// its error message to make it easier to track down the bad JSON data.
type errBadJSON struct {
	msg  string
	json []byte
	err  error
}

// Error returns an error message that includes the json.Unmarshal error as well
// as the bad JSON data.
func (e errBadJSON) Error() string {
	return fmt.Sprintf(
		"%s: error unmarshaling JSON %q: %s",
		e.msg,
		string(e.json),
		e.err)
}

// badJSONError is a convenience function for constructing a errBadJSON instance
// with the provided args.
func badJSONError(msg string, jsonData []byte, err error) error {
	return errBadJSON{
		msg:  msg,
		json: jsonData,
		err:  err,
	}
}

const regFields = "id, jwk, jwk_sha256, contact, agreement, initialIP, createdAt, LockCol, status"

// selectRegistration selects all fields of one registration model
func selectRegistration(s db.OneSelector, q string, args ...interface{}) (*regModel, error) {
	var model regModel
	err := s.SelectOne(
		&model,
		"SELECT "+regFields+" FROM registrations "+q,
		args...,
	)
	return &model, err
}

const certFields = "registrationID, serial, digest, der, issued, expires"

// SelectCertificate selects all fields of one certificate object identified by
// a serial. If more than one row contains the same serial only the first is
// returned.
func SelectCertificate(s db.OneSelector, serial string) (core.Certificate, error) {
	var model core.Certificate
	err := s.SelectOne(
		&model,
		"SELECT "+certFields+" FROM certificates WHERE serial = ? LIMIT 1",
		serial,
	)
	return model, err
}

const precertFields = "registrationID, serial, der, issued, expires"

// SelectPrecertificate selects all fields of one precertificate object
// identified by serial.
func SelectPrecertificate(s db.OneSelector, serial string) (core.Certificate, error) {
	var model precertificateModel
	err := s.SelectOne(
		&model,
		"SELECT "+precertFields+" FROM precertificates WHERE serial = ?",
		serial)
	return core.Certificate{
		RegistrationID: model.RegistrationID,
		Serial:         model.Serial,
		DER:            model.DER,
		Issued:         model.Issued,
		Expires:        model.Expires,
	}, err
}

type CertWithID struct {
	ID int64
	core.Certificate
}

// SelectCertificates selects all fields of multiple certificate objects
func SelectCertificates(s db.Selector, q string, args map[string]interface{}) ([]CertWithID, error) {
	var models []CertWithID
	_, err := s.Select(
		&models,
		"SELECT id, "+certFields+" FROM certificates "+q, args)
	return models, err
}

// SelectPrecertificates selects all fields of multiple precertificate objects.
func SelectPrecertificates(s db.Selector, q string, args map[string]interface{}) ([]CertWithID, error) {
	var models []CertWithID
	_, err := s.Select(
		&models,
		"SELECT id, "+precertFields+" FROM precertificates "+q, args)
	return models, err
}

type CertStatusMetadata struct {
	ID                    int64             `db:"id"`
	Serial                string            `db:"serial"`
	Status                core.OCSPStatus   `db:"status"`
	OCSPLastUpdated       time.Time         `db:"ocspLastUpdated"`
	RevokedDate           time.Time         `db:"revokedDate"`
	RevokedReason         revocation.Reason `db:"revokedReason"`
	LastExpirationNagSent time.Time         `db:"lastExpirationNagSent"`
	NotAfter              time.Time         `db:"notAfter"`
	IsExpired             bool              `db:"isExpired"`
	IssuerID              int64             `db:"issuerID"`
}

const certStatusFields = "id, serial, status, ocspLastUpdated, revokedDate, revokedReason, lastExpirationNagSent, ocspResponse, notAfter, isExpired, issuerID"

// SelectCertificateStatus selects all fields of one certificate status model
// identified by serial
func SelectCertificateStatus(s db.OneSelector, serial string) (core.CertificateStatus, error) {
	var model core.CertificateStatus
	err := s.SelectOne(
		&model,
		"SELECT "+certStatusFields+" FROM certificateStatus WHERE serial = ?",
		serial,
	)
	return model, err
}

var mediumBlobSize = int(math.Pow(2, 24))

type issuedNameModel struct {
	ID           int64     `db:"id"`
	ReversedName string    `db:"reversedName"`
	NotBefore    time.Time `db:"notBefore"`
	Serial       string    `db:"serial"`
}

// regModel is the description of a core.Registration in the database before
type regModel struct {
	ID        int64  `db:"id"`
	Key       []byte `db:"jwk"`
	KeySHA256 string `db:"jwk_sha256"`
	Contact   string `db:"contact"`
	Agreement string `db:"agreement"`
	// InitialIP is stored as sixteen binary bytes, regardless of whether it
	// represents a v4 or v6 IP address.
	InitialIP []byte    `db:"initialIp"`
	CreatedAt time.Time `db:"createdAt"`
	LockCol   int64
	Status    string `db:"status"`
}

func registrationPbToModel(reg *corepb.Registration) (*regModel, error) {
	// Even though we don't need to convert from JSON to an in-memory JSONWebKey
	// for the sake of the `Key` field, we do need to do the conversion in order
	// to compute the SHA256 key digest.
	var jwk jose.JSONWebKey
	err := jwk.UnmarshalJSON(reg.Key)
	if err != nil {
		return nil, err
	}
	sha, err := core.KeyDigestB64(jwk.Key)
	if err != nil {
		return nil, err
	}

	// We don't want to write literal JSON "null" strings into the database if the
	// list of contact addresses is empty. Replace any possibly-`nil` slice with
	// an empty JSON array. We don't need to check reg.ContactPresent, because
	// we're going to write the whole object to the database anyway.
	jsonContact := []byte("[]")
	if len(reg.Contact) != 0 {
		jsonContact, err = json.Marshal(reg.Contact)
		if err != nil {
			return nil, err
		}
	}

	// For some reason we use different serialization formats for InitialIP
	// in database models and in protobufs, despite the fact that both formats
	// are just []byte.
	var initialIP net.IP
	err = initialIP.UnmarshalText(reg.InitialIP)
	if err != nil {
		return nil, err
	}

	// Converting the int64 zero-value to a unix timestamp does not produce
	// the time.Time zero-value (the former is 1970; the latter is year 0),
	// so we have to do this check.
	var createdAt time.Time
	if reg.CreatedAt != 0 {
		createdAt = time.Unix(0, reg.CreatedAt)
	}

	return &regModel{
		ID:        reg.Id,
		Key:       reg.Key,
		KeySHA256: sha,
		Contact:   string(jsonContact),
		Agreement: reg.Agreement,
		InitialIP: []byte(initialIP.To16()),
		CreatedAt: createdAt,
		Status:    reg.Status,
	}, nil
}

func registrationModelToPb(reg *regModel) (*corepb.Registration, error) {
	if reg.ID == 0 || len(reg.Key) == 0 || len(reg.InitialIP) == 0 {
		return nil, errors.New("incomplete Registration retrieved from DB")
	}

	contact := []string{}
	contactsPresent := false
	if len(reg.Contact) > 0 {
		err := json.Unmarshal([]byte(reg.Contact), &contact)
		if err != nil {
			return nil, err
		}
		if len(contact) > 0 {
			contactsPresent = true
		}
	}

	// For some reason we use different serialization formats for InitialIP
	// in database models and in protobufs, despite the fact that both formats
	// are just []byte.
	ipBytes, err := net.IP(reg.InitialIP).MarshalText()
	if err != nil {
		return nil, err
	}

	return &corepb.Registration{
		Id:              reg.ID,
		Key:             reg.Key,
		Contact:         contact,
		ContactsPresent: contactsPresent,
		Agreement:       reg.Agreement,
		InitialIP:       ipBytes,
		CreatedAt:       reg.CreatedAt.UTC().UnixNano(),
		Status:          reg.Status,
	}, nil
}

type recordedSerialModel struct {
	ID             int64
	Serial         string
	RegistrationID int64
	Created        time.Time
	Expires        time.Time
}

type precertificateModel struct {
	ID             int64
	Serial         string
	RegistrationID int64
	DER            []byte
	Issued         time.Time
	Expires        time.Time
}

type orderModel struct {
	ID                int64
	RegistrationID    int64
	Expires           time.Time
	Created           time.Time
	Error             []byte
	CertificateSerial string
	BeganProcessing   bool
}

type requestedNameModel struct {
	ID           int64
	OrderID      int64
	ReversedName string
}

type orderToAuthzModel struct {
	OrderID int64
	AuthzID int64
}

func orderToModel(order *corepb.Order) (*orderModel, error) {
	om := &orderModel{
		ID:                order.Id,
		RegistrationID:    order.RegistrationID,
		Expires:           time.Unix(0, order.Expires),
		Created:           time.Unix(0, order.Created),
		BeganProcessing:   order.BeganProcessing,
		CertificateSerial: order.CertificateSerial,
	}

	if order.Error != nil {
		errJSON, err := json.Marshal(order.Error)
		if err != nil {
			return nil, err
		}
		if len(errJSON) > mediumBlobSize {
			return nil, fmt.Errorf("Error object is too large to store in the database")
		}
		om.Error = errJSON
	}
	return om, nil
}

func modelToOrder(om *orderModel) (*corepb.Order, error) {
	order := &corepb.Order{
		Id:                om.ID,
		RegistrationID:    om.RegistrationID,
		Expires:           om.Expires.UnixNano(),
		Created:           om.Created.UnixNano(),
		CertificateSerial: om.CertificateSerial,
		BeganProcessing:   om.BeganProcessing,
	}
	if len(om.Error) > 0 {
		var problem corepb.ProblemDetails
		err := json.Unmarshal(om.Error, &problem)
		if err != nil {
			return &corepb.Order{}, badJSONError(
				"failed to unmarshal order model's error",
				om.Error,
				err)
		}
		order.Error = &problem
	}
	return order, nil
}

var challTypeToUint = map[string]uint8{
	"http-01":     0,
	"dns-01":      1,
	"tls-alpn-01": 2,
}

var uintToChallType = map[uint8]string{
	0: "http-01",
	1: "dns-01",
	2: "tls-alpn-01",
}

var identifierTypeToUint = map[string]uint8{
	"dns": 0,
}

var uintToIdentifierType = map[uint8]string{
	0: "dns",
}

var statusToUint = map[core.AcmeStatus]uint8{
	core.StatusPending:     0,
	core.StatusValid:       1,
	core.StatusInvalid:     2,
	core.StatusDeactivated: 3,
	core.StatusRevoked:     4,
}

var uintToStatus = map[uint8]core.AcmeStatus{
	0: core.StatusPending,
	1: core.StatusValid,
	2: core.StatusInvalid,
	3: core.StatusDeactivated,
	4: core.StatusRevoked,
}

func statusUint(status core.AcmeStatus) uint8 {
	return statusToUint[status]
}

// authzFields is used in a variety of places in sa.go, and modifications to
// it must be carried through to every use in sa.go
const authzFields = "id, identifierType, identifierValue, registrationID, status, expires, challenges, attempted, attemptedAt, token, validationError, validationRecord"

type authzModel struct {
	ID               int64      `db:"id"`
	IdentifierType   uint8      `db:"identifierType"`
	IdentifierValue  string     `db:"identifierValue"`
	RegistrationID   int64      `db:"registrationID"`
	Status           uint8      `db:"status"`
	Expires          time.Time  `db:"expires"`
	Challenges       uint8      `db:"challenges"`
	Attempted        *uint8     `db:"attempted"`
	AttemptedAt      *time.Time `db:"attemptedAt"`
	Token            []byte     `db:"token"`
	ValidationError  []byte     `db:"validationError"`
	ValidationRecord []byte     `db:"validationRecord"`
}

// hasMultipleNonPendingChallenges checks if a slice of challenges contains
// more than one non-pending challenge
func hasMultipleNonPendingChallenges(challenges []*corepb.Challenge) bool {
	nonPending := false
	for _, c := range challenges {
		if c.Status == string(core.StatusValid) || c.Status == string(core.StatusInvalid) {
			if !nonPending {
				nonPending = true
			} else {
				return true
			}
		}
	}
	return false
}

// authzPBToModel converts a protobuf authorization representation to the
// authzModel storage representation.
func authzPBToModel(authz *corepb.Authorization) (*authzModel, error) {
	am := &authzModel{
		IdentifierValue: authz.Identifier,
		RegistrationID:  authz.RegistrationID,
		Status:          statusToUint[core.AcmeStatus(authz.Status)],
		Expires:         time.Unix(0, authz.Expires).UTC(),
	}
	if authz.Id != "" {
		// The v1 internal authorization objects use a string for the ID, the v2
		// storage format uses a integer ID. In order to maintain compatibility we
		// convert the integer ID to a string.
		id, err := strconv.Atoi(authz.Id)
		if err != nil {
			return nil, err
		}
		am.ID = int64(id)
	}
	if hasMultipleNonPendingChallenges(authz.Challenges) {
		return nil, errors.New("multiple challenges are non-pending")
	}
	// In the v2 authorization style we don't store individual challenges with their own
	// token, validation errors/records, etc. Instead we store a single token/error/record
	// set, a bitmap of available challenge types, and a row indicating which challenge type
	// was 'attempted'.
	//
	// Since we don't currently have the singular token/error/record set abstracted out to
	// the core authorization type yet we need to extract these from the challenges array.
	// We assume that the token in each challenge is the same and that if any of the challenges
	// has a non-pending status that it should be considered the 'attempted' challenge and
	// we extract the error/record set from that particular challenge.
	var tokenStr string
	for _, chall := range authz.Challenges {
		// Set the challenge type bit in the bitmap
		am.Challenges |= 1 << challTypeToUint[chall.Type]
		tokenStr = chall.Token
		// If the challenge status is not core.StatusPending we assume it was the 'attempted'
		// challenge and extract the relevant fields we need.
		if chall.Status == string(core.StatusValid) || chall.Status == string(core.StatusInvalid) {
			attemptedType := challTypeToUint[chall.Type]
			am.Attempted = &attemptedType

			// If validated Unix timestamp is zero then keep the core.Challenge Validated object nil.
			var validated *time.Time
			if chall.Validated != 0 {
				val := time.Unix(0, chall.Validated).UTC()
				validated = &val
			}
			am.AttemptedAt = validated

			// Marshal corepb.ValidationRecords to core.ValidationRecords so that we
			// can marshal them to JSON.
			records := make([]core.ValidationRecord, len(chall.Validationrecords))
			for i, recordPB := range chall.Validationrecords {
				var err error
				records[i], err = grpc.PBToValidationRecord(recordPB)
				if err != nil {
					return nil, err
				}
			}
			var err error
			am.ValidationRecord, err = json.Marshal(records)
			if err != nil {
				return nil, err
			}
			// If there is a error associated with the challenge marshal it to JSON
			// so that we can store it in the database.
			if chall.Error != nil {
				prob, err := grpc.PBToProblemDetails(chall.Error)
				if err != nil {
					return nil, err
				}
				am.ValidationError, err = json.Marshal(prob)
				if err != nil {
					return nil, err
				}
			}
		}
		token, err := base64.RawURLEncoding.DecodeString(tokenStr)
		if err != nil {
			return nil, err
		}
		am.Token = token
	}

	return am, nil
}

// populateAttemptedFields takes a challenge and populates it with the validation fields status,
// validation records, and error (the latter only if the validation failed) from a authzModel.
func populateAttemptedFields(am authzModel, challenge *corepb.Challenge) error {
	if len(am.ValidationError) != 0 {
		// If the error is non-empty the challenge must be invalid.
		challenge.Status = string(core.StatusInvalid)
		var prob probs.ProblemDetails
		err := json.Unmarshal(am.ValidationError, &prob)
		if err != nil {
			return badJSONError(
				"failed to unmarshal authz2 model's validation error",
				am.ValidationError,
				err)
		}
		challenge.Error, err = grpc.ProblemDetailsToPB(&prob)
		if err != nil {
			return err
		}
	} else {
		// If the error is empty the challenge must be valid.
		challenge.Status = string(core.StatusValid)
	}
	var records []core.ValidationRecord
	err := json.Unmarshal(am.ValidationRecord, &records)
	if err != nil {
		return badJSONError(
			"failed to unmarshal authz2 model's validation record",
			am.ValidationRecord,
			err)
	}
	challenge.Validationrecords = make([]*corepb.ValidationRecord, len(records))
	for i, r := range records {
		challenge.Validationrecords[i], err = grpc.ValidationRecordToPB(r)
		if err != nil {
			return err
		}
	}
	return nil
}

func modelToAuthzPB(am authzModel) (*corepb.Authorization, error) {
	pb := &corepb.Authorization{
		Id:             fmt.Sprintf("%d", am.ID),
		Status:         string(uintToStatus[am.Status]),
		Identifier:     am.IdentifierValue,
		RegistrationID: am.RegistrationID,
		Expires:        am.Expires.UTC().UnixNano(),
	}
	// Populate authorization challenge array. We do this by iterating through
	// the challenge type bitmap and creating a challenge of each type if its
	// bit is set. Each of these challenges has the token from the authorization
	// model and has its status set to core.StatusPending by default. If the
	// challenge type is equal to that in the 'attempted' row we set the status
	// to core.StatusValid or core.StatusInvalid depending on if there is anything
	// in ValidationError and populate the ValidationRecord and ValidationError
	// fields.
	for pos := uint8(0); pos < 8; pos++ {
		if (am.Challenges>>pos)&1 == 1 {
			challType := uintToChallType[pos]
			challenge := &corepb.Challenge{
				Type:   challType,
				Status: string(core.StatusPending),
				Token:  base64.RawURLEncoding.EncodeToString(am.Token),
			}
			// If the challenge type matches the attempted type it must be either
			// valid or invalid and we need to populate extra fields.
			// Also, once any challenge has been attempted, we consider the other
			// challenges "gone" per https://tools.ietf.org/html/rfc8555#section-7.1.4
			if am.Attempted != nil {
				if uintToChallType[*am.Attempted] == challType {
					err := populateAttemptedFields(am, challenge)
					if err != nil {
						return nil, err
					}
					// Get the attemptedAt time and assign to the challenge validated time.
					var validated int64
					if am.AttemptedAt != nil {
						validated = am.AttemptedAt.UTC().UnixNano()
					}
					challenge.Validated = validated
					pb.Challenges = append(pb.Challenges, challenge)
				}
			} else {
				// When no challenge has been attempted yet, all challenges are still
				// present.
				pb.Challenges = append(pb.Challenges, challenge)
			}
		}
	}
	return pb, nil
}

type keyHashModel struct {
	ID           int64
	KeyHash      []byte
	CertNotAfter time.Time
	CertSerial   string
}

var stringToSourceInt = map[string]int{
	"API":           1,
	"admin-revoker": 2,
}

// incidentModel represents a row in the 'incidents' table.
type incidentModel struct {
	ID          int64     `db:"id"`
	SerialTable string    `db:"serialTable"`
	URL         string    `db:"url"`
	RenewBy     time.Time `db:"renewBy"`
	Enabled     bool      `db:"enabled"`
}

func incidentModelToPB(i incidentModel) sapb.Incident {
	return sapb.Incident{
		Id:          i.ID,
		SerialTable: i.SerialTable,
		Url:         i.URL,
		RenewBy:     i.RenewBy.UnixNano(),
		Enabled:     i.Enabled,
	}
}

// incidentSerialModel represents a row in an 'incident_*' table.
type incidentSerialModel struct {
	Serial         string    `db:"serial"`
	RegistrationID int64     `db:"registrationID"`
	OrderID        int64     `db:"orderID"`
	LastNoticeSent time.Time `db:"lastNoticeSent"`
}

// crlEntryModel has just the certificate status fields necessary to construct
// an entry in a CRL.
type crlEntryModel struct {
	Serial        string            `db:"serial"`
	Status        core.OCSPStatus   `db:"status"`
	RevokedReason revocation.Reason `db:"revokedReason"`
	RevokedDate   time.Time         `db:"revokedDate"`
}
