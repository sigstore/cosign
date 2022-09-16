package sa

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/ocsp"
	"google.golang.org/protobuf/types/known/emptypb"
	jose "gopkg.in/square/go-jose.v2"

	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/db"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/features"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/identifier"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/revocation"
	rocsp_config "github.com/letsencrypt/boulder/rocsp/config"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

var (
	errIncompleteRequest     = errors.New("incomplete gRPC request message")
	validIncidentTableRegexp = regexp.MustCompile(`^incident_[0-9a-zA-Z_]{1,100}$`)
)

type certCountFunc func(db db.Selector, domain string, timeRange *sapb.Range) (int64, error)

// SQLStorageAuthority defines a Storage Authority
type SQLStorageAuthority struct {
	sapb.UnimplementedStorageAuthorityServer
	dbMap         *db.WrappedMap
	dbReadOnlyMap *db.WrappedMap

	// Short issuer map used by rocsp.
	shortIssuers []rocsp_config.ShortIDIssuer

	clk clock.Clock
	log blog.Logger

	// For RPCs that generate multiple, parallelizable SQL queries, this is the
	// max parallelism they will use (to avoid consuming too many MariaDB
	// threads).
	parallelismPerRPC int

	// We use function types here so we can mock out this internal function in
	// unittests.
	countCertificatesByName certCountFunc

	// rateLimitWriteErrors is a Counter for the number of times
	// a ratelimit update transaction failed during AddCertificate request
	// processing. We do not fail the overall AddCertificate call when ratelimit
	// transactions fail and so use this stat to maintain visibility into the rate
	// this occurs.
	rateLimitWriteErrors prometheus.Counter

	// redisStoreResponse is a counter of OCSP responses written to redis by
	// result.
	redisStoreResponse *prometheus.CounterVec
}

// orderFQDNSet contains the SHA256 hash of the lowercased, comma joined names
// from a new-order request, along with the corresponding orderID, the
// registration ID, and the order expiry. This is used to find
// existing orders for reuse.
type orderFQDNSet struct {
	ID             int64
	SetHash        []byte
	OrderID        int64
	RegistrationID int64
	Expires        time.Time
}

// NewSQLStorageAuthority provides persistence using a SQL backend for
// Boulder. It will modify the given gorp.DbMap by adding relevant tables.
func NewSQLStorageAuthority(
	dbMap *db.WrappedMap,
	dbReadOnlyMap *db.WrappedMap,
	shortIssuers []rocsp_config.ShortIDIssuer,
	clk clock.Clock,
	logger blog.Logger,
	stats prometheus.Registerer,
	parallelismPerRPC int,
) (*SQLStorageAuthority, error) {
	SetSQLDebug(dbMap, logger)

	rateLimitWriteErrors := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "rate_limit_write_errors",
		Help: "number of failed ratelimit update transactions during AddCertificate",
	})
	stats.MustRegister(rateLimitWriteErrors)

	redisStoreResponse := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "redis_store_response",
		Help: "Count of OCSP Response writes to redis",
	}, []string{"result"})
	stats.MustRegister(redisStoreResponse)

	ssa := &SQLStorageAuthority{
		dbMap:                dbMap,
		dbReadOnlyMap:        dbReadOnlyMap,
		shortIssuers:         shortIssuers,
		clk:                  clk,
		log:                  logger,
		parallelismPerRPC:    parallelismPerRPC,
		rateLimitWriteErrors: rateLimitWriteErrors,
		redisStoreResponse:   redisStoreResponse,
	}

	ssa.countCertificatesByName = ssa.countCertificates

	return ssa, nil
}

// GetRegistration obtains a Registration by ID
func (ssa *SQLStorageAuthority) GetRegistration(ctx context.Context, req *sapb.RegistrationID) (*corepb.Registration, error) {
	if req == nil || req.Id == 0 {
		return nil, errIncompleteRequest
	}

	const query = "WHERE id = ?"
	model, err := selectRegistration(ssa.dbMap.WithContext(ctx), query, req.Id)
	if err != nil {
		if db.IsNoRows(err) {
			return nil, berrors.NotFoundError("registration with ID '%d' not found", req.Id)
		}
		return nil, err
	}

	return registrationModelToPb(model)
}

// GetRegistrationByKey obtains a Registration by JWK
func (ssa *SQLStorageAuthority) GetRegistrationByKey(ctx context.Context, req *sapb.JSONWebKey) (*corepb.Registration, error) {
	if req == nil || len(req.Jwk) == 0 {
		return nil, errIncompleteRequest
	}

	var jwk jose.JSONWebKey
	err := jwk.UnmarshalJSON(req.Jwk)
	if err != nil {
		return nil, err
	}

	const query = "WHERE jwk_sha256 = ?"
	sha, err := core.KeyDigestB64(jwk.Key)
	if err != nil {
		return nil, err
	}
	model, err := selectRegistration(ssa.dbMap.WithContext(ctx), query, sha)
	if err != nil {
		if db.IsNoRows(err) {
			return nil, berrors.NotFoundError("no registrations with public key sha256 %q", sha)
		}
		return nil, err
	}

	return registrationModelToPb(model)
}

// incrementIP returns a copy of `ip` incremented at a bit index `index`,
// or in other words the first IP of the next highest subnet given a mask of
// length `index`.
// In order to easily account for overflow, we treat ip as a big.Int and add to
// it. If the increment overflows the max size of a net.IP, return the highest
// possible net.IP.
func incrementIP(ip net.IP, index int) net.IP {
	bigInt := new(big.Int)
	bigInt.SetBytes([]byte(ip))
	incr := new(big.Int).Lsh(big.NewInt(1), 128-uint(index))
	bigInt.Add(bigInt, incr)
	// bigInt.Bytes can be shorter than 16 bytes, so stick it into a
	// full-sized net.IP.
	resultBytes := bigInt.Bytes()
	if len(resultBytes) > 16 {
		return net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	}
	result := make(net.IP, 16)
	copy(result[16-len(resultBytes):], resultBytes)
	return result
}

// ipRange returns a range of IP addresses suitable for querying MySQL for the
// purpose of rate limiting using a range that is inclusive on the lower end and
// exclusive at the higher end. If ip is an IPv4 address, it returns that address,
// plus the one immediately higher than it. If ip is an IPv6 address, it applies
// a /48 mask to it and returns the lowest IP in the resulting network, and the
// first IP outside of the resulting network.
func ipRange(ip net.IP) (net.IP, net.IP) {
	ip = ip.To16()
	// For IPv6, match on a certain subnet range, since one person can commonly
	// have an entire /48 to themselves.
	maskLength := 48
	// For IPv4 addresses, do a match on exact address, so begin = ip and end =
	// next higher IP.
	if ip.To4() != nil {
		maskLength = 128
	}

	mask := net.CIDRMask(maskLength, 128)
	begin := ip.Mask(mask)
	end := incrementIP(begin, maskLength)

	return begin, end
}

// CountRegistrationsByIP returns the number of registrations created in the
// time range for a single IP address.
func (ssa *SQLStorageAuthority) CountRegistrationsByIP(ctx context.Context, req *sapb.CountRegistrationsByIPRequest) (*sapb.Count, error) {
	if len(req.Ip) == 0 || req.Range.Earliest == 0 || req.Range.Latest == 0 {
		return nil, errIncompleteRequest
	}

	var count int64
	err := ssa.dbReadOnlyMap.WithContext(ctx).SelectOne(
		&count,
		`SELECT COUNT(1) FROM registrations
		 WHERE
		 initialIP = :ip AND
		 :earliest < createdAt AND
		 createdAt <= :latest`,
		map[string]interface{}{
			"ip":       req.Ip,
			"earliest": time.Unix(0, req.Range.Earliest),
			"latest":   time.Unix(0, req.Range.Latest),
		})
	if err != nil {
		return &sapb.Count{Count: -1}, err
	}
	return &sapb.Count{Count: count}, nil
}

// CountRegistrationsByIPRange returns the number of registrations created in
// the time range in an IP range. For IPv4 addresses, that range is limited to
// the single IP. For IPv6 addresses, that range is a /48, since it's not
// uncommon for one person to have a /48 to themselves.
func (ssa *SQLStorageAuthority) CountRegistrationsByIPRange(ctx context.Context, req *sapb.CountRegistrationsByIPRequest) (*sapb.Count, error) {
	if len(req.Ip) == 0 || req.Range.Earliest == 0 || req.Range.Latest == 0 {
		return nil, errIncompleteRequest
	}

	var count int64
	beginIP, endIP := ipRange(req.Ip)
	err := ssa.dbReadOnlyMap.WithContext(ctx).SelectOne(
		&count,
		`SELECT COUNT(1) FROM registrations
		 WHERE
		 :beginIP <= initialIP AND
		 initialIP < :endIP AND
		 :earliest < createdAt AND
		 createdAt <= :latest`,
		map[string]interface{}{
			"earliest": time.Unix(0, req.Range.Earliest),
			"latest":   time.Unix(0, req.Range.Latest),
			"beginIP":  beginIP,
			"endIP":    endIP,
		})
	if err != nil {
		return &sapb.Count{Count: -1}, err
	}
	return &sapb.Count{Count: count}, nil
}

// CountCertificatesByNames counts, for each input domain, the number of
// certificates issued in the given time range for that domain and its
// subdomains. It returns a map from domains to counts, which is guaranteed to
// contain an entry for each input domain, so long as err is nil.
// Queries will be run in parallel. If any of them error, only one error will
// be returned.
func (ssa *SQLStorageAuthority) CountCertificatesByNames(ctx context.Context, req *sapb.CountCertificatesByNamesRequest) (*sapb.CountByNames, error) {
	if len(req.Names) == 0 || req.Range.Earliest == 0 || req.Range.Latest == 0 {
		return nil, errIncompleteRequest
	}

	work := make(chan string, len(req.Names))
	type result struct {
		err    error
		count  int64
		domain string
	}
	results := make(chan result, len(req.Names))
	for _, domain := range req.Names {
		work <- domain
	}
	close(work)
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// We may perform up to 100 queries, depending on what's in the certificate
	// request. Parallelize them so we don't hit our timeout, but limit the
	// parallelism so we don't consume too many threads on the database.
	for i := 0; i < ssa.parallelismPerRPC; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range work {
				select {
				case <-ctx.Done():
					results <- result{err: ctx.Err()}
					return
				default:
				}
				currentCount, err := ssa.countCertificatesByName(ssa.dbReadOnlyMap.WithContext(ctx), domain, req.Range)
				if err != nil {
					results <- result{err: err}
					// Skip any further work
					cancel()
					return
				}
				results <- result{
					count:  currentCount,
					domain: domain,
				}
			}
		}()
	}
	wg.Wait()
	close(results)
	counts := make(map[string]int64)
	for r := range results {
		if r.err != nil {
			return nil, r.err
		}
		counts[r.domain] = r.count
	}
	return &sapb.CountByNames{Counts: counts}, nil
}

func ReverseName(domain string) string {
	labels := strings.Split(domain, ".")
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
	return strings.Join(labels, ".")
}

// GetCertificate takes a serial number and returns the corresponding
// certificate, or error if it does not exist.
func (ssa *SQLStorageAuthority) GetCertificate(ctx context.Context, req *sapb.Serial) (*corepb.Certificate, error) {
	if req == nil || req.Serial == "" {
		return nil, errIncompleteRequest
	}
	if !core.ValidSerial(req.Serial) {
		return nil, fmt.Errorf("Invalid certificate serial %s", req.Serial)
	}

	cert, err := SelectCertificate(ssa.dbMap.WithContext(ctx), req.Serial)
	if db.IsNoRows(err) {
		return nil, berrors.NotFoundError("certificate with serial %q not found", req.Serial)
	}
	if err != nil {
		return nil, err
	}
	return bgrpc.CertToPB(cert), nil
}

// GetCertificateStatus takes a hexadecimal string representing the full 128-bit serial
// number of a certificate and returns data about that certificate's current
// validity.
func (ssa *SQLStorageAuthority) GetCertificateStatus(ctx context.Context, req *sapb.Serial) (*corepb.CertificateStatus, error) {
	if req.Serial == "" {
		return nil, errIncompleteRequest
	}
	if !core.ValidSerial(req.Serial) {
		err := fmt.Errorf("Invalid certificate serial %s", req.Serial)
		return nil, err
	}

	certStatus, err := SelectCertificateStatus(ssa.dbMap.WithContext(ctx), req.Serial)
	if db.IsNoRows(err) {
		return nil, berrors.NotFoundError("certificate status with serial %q not found", req.Serial)
	}
	if err != nil {
		return nil, err
	}

	return bgrpc.CertStatusToPB(certStatus), nil
}

// NewRegistration stores a new Registration
func (ssa *SQLStorageAuthority) NewRegistration(ctx context.Context, req *corepb.Registration) (*corepb.Registration, error) {
	if len(req.Key) == 0 || len(req.InitialIP) == 0 {
		return nil, errIncompleteRequest
	}

	reg, err := registrationPbToModel(req)
	if err != nil {
		return nil, err
	}

	reg.CreatedAt = ssa.clk.Now()

	err = ssa.dbMap.WithContext(ctx).Insert(reg)
	if err != nil {
		if db.IsDuplicate(err) {
			// duplicate entry error can only happen when jwk_sha256 collides, indicate
			// to caller that the provided key is already in use
			return nil, berrors.DuplicateError("key is already in use for a different account")
		}
		return nil, err
	}
	return registrationModelToPb(reg)
}

// UpdateRegistration stores an updated Registration
func (ssa *SQLStorageAuthority) UpdateRegistration(ctx context.Context, req *corepb.Registration) (*emptypb.Empty, error) {
	if req == nil || req.Id == 0 || len(req.Key) == 0 || len(req.InitialIP) == 0 {
		return nil, errIncompleteRequest
	}

	const query = "WHERE id = ?"
	curr, err := selectRegistration(ssa.dbMap.WithContext(ctx), query, req.Id)
	if err != nil {
		if db.IsNoRows(err) {
			return nil, berrors.NotFoundError("registration with ID '%d' not found", req.Id)
		}
		return nil, err
	}

	update, err := registrationPbToModel(req)
	if err != nil {
		return nil, err
	}

	// Copy the existing registration model's LockCol to the new updated
	// registration model's LockCol
	update.LockCol = curr.LockCol
	n, err := ssa.dbMap.WithContext(ctx).Update(update)
	if err != nil {
		if db.IsDuplicate(err) {
			// duplicate entry error can only happen when jwk_sha256 collides, indicate
			// to caller that the provided key is already in use
			return nil, berrors.DuplicateError("key is already in use for a different account")
		}
		return nil, err
	}
	if n == 0 {
		return nil, berrors.NotFoundError("registration with ID '%d' not found", req.Id)
	}

	return &emptypb.Empty{}, nil
}

// AddCertificate stores an issued certificate and returns the digest as
// a string, or an error if any occurred.
func (ssa *SQLStorageAuthority) AddCertificate(ctx context.Context, req *sapb.AddCertificateRequest) (*sapb.AddCertificateResponse, error) {
	if len(req.Der) == 0 || req.RegID == 0 || req.Issued == 0 {
		return nil, errIncompleteRequest
	}
	parsedCertificate, err := x509.ParseCertificate(req.Der)
	if err != nil {
		return nil, err
	}
	digest := core.Fingerprint256(req.Der)
	serial := core.SerialToString(parsedCertificate.SerialNumber)

	cert := &core.Certificate{
		RegistrationID: req.RegID,
		Serial:         serial,
		Digest:         digest,
		DER:            req.Der,
		Issued:         time.Unix(0, req.Issued),
		Expires:        parsedCertificate.NotAfter,
	}

	isRenewalRaw, overallError := db.WithTransaction(ctx, ssa.dbMap, func(txWithCtx db.Executor) (interface{}, error) {
		// Select to see if cert exists
		var row struct {
			Count int64
		}
		err := txWithCtx.SelectOne(&row, "SELECT count(1) as count FROM certificates WHERE serial=?", serial)
		if err != nil {
			return nil, err
		}
		if row.Count > 0 {
			return nil, berrors.DuplicateError("cannot add a duplicate cert")
		}

		// Save the final certificate
		err = txWithCtx.Insert(cert)
		if err != nil {
			return nil, err
		}

		// NOTE(@cpu): When we collect up names to check if an FQDN set exists (e.g.
		// that it is a renewal) we use just the DNSNames from the certificate and
		// ignore the Subject Common Name (if any). This is a safe assumption because
		// if a certificate we issued were to have a Subj. CN not present as a SAN it
		// would be a misissuance and miscalculating whether the cert is a renewal or
		// not for the purpose of rate limiting is the least of our troubles.
		isRenewal, err := ssa.checkFQDNSetExists(
			txWithCtx.SelectOne,
			parsedCertificate.DNSNames)
		if err != nil {
			return nil, err
		}

		return isRenewal, err
	})
	if overallError != nil {
		return nil, overallError
	}

	// Recast the interface{} return from db.WithTransaction as a bool, returning
	// an error if we can't.
	var isRenewal bool
	if boolVal, ok := isRenewalRaw.(bool); !ok {
		return nil, fmt.Errorf(
			"AddCertificate db.WithTransaction returned %T out var, expected bool",
			isRenewalRaw)
	} else {
		isRenewal = boolVal
	}

	// In a separate transaction perform the work required to update tables used
	// for rate limits. Since the effects of failing these writes is slight
	// miscalculation of rate limits we choose to not fail the AddCertificate
	// operation if the rate limit update transaction fails.
	_, rlTransactionErr := db.WithTransaction(ctx, ssa.dbMap, func(txWithCtx db.Executor) (interface{}, error) {
		// Add to the rate limit table, but only for new certificates. Renewals
		// don't count against the certificatesPerName limit.
		if !isRenewal {
			timeToTheHour := parsedCertificate.NotBefore.Round(time.Hour)
			err := ssa.addCertificatesPerName(ctx, txWithCtx, parsedCertificate.DNSNames, timeToTheHour)
			if err != nil {
				return nil, err
			}
		}

		// Update the FQDN sets now that there is a final certificate to ensure rate
		// limits are calculated correctly.
		err = addFQDNSet(
			txWithCtx,
			parsedCertificate.DNSNames,
			core.SerialToString(parsedCertificate.SerialNumber),
			parsedCertificate.NotBefore,
			parsedCertificate.NotAfter,
		)
		if err != nil {
			return nil, err
		}

		return nil, nil
	})
	// If the ratelimit transaction failed increment a stat and log a warning
	// but don't return an error from AddCertificate.
	if rlTransactionErr != nil {
		ssa.rateLimitWriteErrors.Inc()
		ssa.log.AuditErrf("failed AddCertificate ratelimit update transaction: %v", rlTransactionErr)
	}

	return &sapb.AddCertificateResponse{Digest: digest}, nil
}

func (ssa *SQLStorageAuthority) CountOrders(ctx context.Context, req *sapb.CountOrdersRequest) (*sapb.Count, error) {
	if req.AccountID == 0 || req.Range.Earliest == 0 || req.Range.Latest == 0 {
		return nil, errIncompleteRequest
	}

	if features.Enabled(features.FasterNewOrdersRateLimit) {
		return countNewOrders(ctx, ssa.dbReadOnlyMap, req)
	}

	var count int64
	err := ssa.dbReadOnlyMap.WithContext(ctx).SelectOne(
		&count,
		`SELECT count(1) FROM orders
		WHERE registrationID = :acctID AND
		created >= :earliest AND
		created < :latest`,
		map[string]interface{}{
			"acctID":   req.AccountID,
			"earliest": time.Unix(0, req.Range.Earliest),
			"latest":   time.Unix(0, req.Range.Latest),
		},
	)
	if err != nil {
		return nil, err
	}

	return &sapb.Count{Count: count}, nil
}

// HashNames returns a hash of the names requested. This is intended for use
// when interacting with the orderFqdnSets table.
func HashNames(names []string) []byte {
	names = core.UniqueLowerNames(names)
	hash := sha256.Sum256([]byte(strings.Join(names, ",")))
	return hash[:]
}

func addFQDNSet(db db.Inserter, names []string, serial string, issued time.Time, expires time.Time) error {
	return db.Insert(&core.FQDNSet{
		SetHash: HashNames(names),
		Serial:  serial,
		Issued:  issued,
		Expires: expires,
	})
}

// addOrderFQDNSet creates a new OrderFQDNSet row using the provided
// information. This function accepts a transaction so that the orderFqdnSet
// addition can take place within the order addition transaction. The caller is
// required to rollback the transaction if an error is returned.
func addOrderFQDNSet(
	db db.Inserter,
	names []string,
	orderID int64,
	regID int64,
	expires time.Time) error {
	return db.Insert(&orderFQDNSet{
		SetHash:        HashNames(names),
		OrderID:        orderID,
		RegistrationID: regID,
		Expires:        expires,
	})
}

// deleteOrderFQDNSet deletes a OrderFQDNSet row that matches the provided
// orderID. This function accepts a transaction so that the deletion can
// take place within the finalization transaction. The caller is required to
// rollback the transaction if an error is returned.
func deleteOrderFQDNSet(
	db db.Execer,
	orderID int64) error {

	result, err := db.Exec(`
	  DELETE FROM orderFqdnSets
		WHERE orderID = ?`,
		orderID)
	if err != nil {
		return err
	}
	rowsDeleted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	// We always expect there to be an order FQDN set row for each
	// pending/processing order that is being finalized. If there isn't one then
	// something is amiss and should be raised as an internal server error
	if rowsDeleted == 0 {
		return berrors.InternalServerError("No orderFQDNSet exists to delete")
	}
	return nil
}

func addIssuedNames(db db.Execer, cert *x509.Certificate, isRenewal bool) error {
	if len(cert.DNSNames) == 0 {
		return berrors.InternalServerError("certificate has no DNSNames")
	}
	var qmarks []string
	var values []interface{}
	for _, name := range cert.DNSNames {
		values = append(values,
			ReverseName(name),
			core.SerialToString(cert.SerialNumber),
			cert.NotBefore,
			isRenewal)
		qmarks = append(qmarks, "(?, ?, ?, ?)")
	}
	query := `INSERT INTO issuedNames (reversedName, serial, notBefore, renewal) VALUES ` + strings.Join(qmarks, ", ") + `;`
	_, err := db.Exec(query, values...)
	return err
}

// CountFQDNSets counts the total number of issuances, for a set of domains,
// that occurred during a given window of time.
func (ssa *SQLStorageAuthority) CountFQDNSets(ctx context.Context, req *sapb.CountFQDNSetsRequest) (*sapb.Count, error) {
	if req.Window == 0 || len(req.Domains) == 0 {
		return nil, errIncompleteRequest
	}

	var count int64
	err := ssa.dbReadOnlyMap.WithContext(ctx).SelectOne(
		&count,
		`SELECT COUNT(1) FROM fqdnSets
		WHERE setHash = ?
		AND issued > ?`,
		HashNames(req.Domains),
		ssa.clk.Now().Add(-time.Duration(req.Window)),
	)
	return &sapb.Count{Count: count}, err
}

// FQDNSetTimestampsForWindow returns the issuance timestamps for each
// certificate, issued for a set of domains, during a given window of time, in
// ascending order.
func (ssa *SQLStorageAuthority) FQDNSetTimestampsForWindow(ctx context.Context, req *sapb.CountFQDNSetsRequest) (*sapb.Timestamps, error) {
	if req.Window == 0 || len(req.Domains) == 0 {
		return nil, errIncompleteRequest
	}
	type row struct {
		Issued time.Time
	}
	var rows []row
	_, err := ssa.dbReadOnlyMap.WithContext(ctx).Select(
		&rows,
		`SELECT issued FROM fqdnSets 
		WHERE setHash = ?
		AND issued > ?
		ORDER BY issued ASC`,
		HashNames(req.Domains),
		ssa.clk.Now().Add(-time.Duration(req.Window)),
	)
	if err != nil {
		return nil, err
	}

	var results []int64
	for _, i := range rows {
		results = append(results, i.Issued.UnixNano())
	}
	return &sapb.Timestamps{Timestamps: results}, nil
}

// FQDNSetExists returns a bool indicating if one or more FQDN sets |names|
// exists in the database
func (ssa *SQLStorageAuthority) FQDNSetExists(ctx context.Context, req *sapb.FQDNSetExistsRequest) (*sapb.Exists, error) {
	if len(req.Domains) == 0 {
		return nil, errIncompleteRequest
	}
	exists, err := ssa.checkFQDNSetExists(ssa.dbMap.WithContext(ctx).SelectOne, req.Domains)
	if err != nil {
		return nil, err
	}
	return &sapb.Exists{Exists: exists}, nil
}

// oneSelectorFunc is a func type that matches both gorp.Transaction.SelectOne
// and gorp.DbMap.SelectOne.
type oneSelectorFunc func(holder interface{}, query string, args ...interface{}) error

// checkFQDNSetExists uses the given oneSelectorFunc to check whether an fqdnSet
// for the given names exists.
func (ssa *SQLStorageAuthority) checkFQDNSetExists(selector oneSelectorFunc, names []string) (bool, error) {
	namehash := HashNames(names)
	var exists bool
	err := selector(
		&exists,
		`SELECT EXISTS (SELECT id FROM fqdnSets WHERE setHash = ? LIMIT 1)`,
		namehash,
	)
	return exists, err
}

// PreviousCertificateExists returns true iff there was at least one certificate
// issued with the provided domain name, and the most recent such certificate
// was issued by the provided registration ID. This method is currently only
// used to determine if a certificate has previously been issued for a given
// domain name in order to determine if validations should be allowed during
// the v1 API shutoff.
// TODO(#5816): Consider removing this method, as it has no callers.
func (ssa *SQLStorageAuthority) PreviousCertificateExists(ctx context.Context, req *sapb.PreviousCertificateExistsRequest) (*sapb.Exists, error) {
	if req.Domain == "" || req.RegID == 0 {
		return nil, errIncompleteRequest
	}

	exists := &sapb.Exists{Exists: true}
	notExists := &sapb.Exists{Exists: false}

	// Find the most recently issued certificate containing this domain name.
	var serial string
	err := ssa.dbMap.WithContext(ctx).SelectOne(
		&serial,
		`SELECT serial FROM issuedNames
		WHERE reversedName = ?
		ORDER BY notBefore DESC
		LIMIT 1`,
		ReverseName(req.Domain),
	)
	if err != nil {
		if db.IsNoRows(err) {
			return notExists, nil
		}
		return nil, err
	}

	// Check whether that certificate was issued to the specified account.
	var count int
	err = ssa.dbMap.WithContext(ctx).SelectOne(
		&count,
		`SELECT COUNT(1) FROM certificates
		WHERE serial = ?
		AND registrationID = ?`,
		serial,
		req.RegID,
	)
	if err != nil {
		// If no rows found, that means the certificate we found in issuedNames wasn't
		// issued by the registration ID we are checking right now, but is not an
		// error.
		if db.IsNoRows(err) {
			return notExists, nil
		}
		return nil, err
	}
	if count > 0 {
		return exists, nil
	}
	return notExists, nil
}

// DeactivateRegistration deactivates a currently valid registration
func (ssa *SQLStorageAuthority) DeactivateRegistration(ctx context.Context, req *sapb.RegistrationID) (*emptypb.Empty, error) {
	if req == nil || req.Id == 0 {
		return nil, errIncompleteRequest
	}
	_, err := ssa.dbMap.WithContext(ctx).Exec(
		"UPDATE registrations SET status = ? WHERE status = ? AND id = ?",
		string(core.StatusDeactivated),
		string(core.StatusValid),
		req.Id,
	)
	if err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

// DeactivateAuthorization2 deactivates a currently valid or pending authorization.
func (ssa *SQLStorageAuthority) DeactivateAuthorization2(ctx context.Context, req *sapb.AuthorizationID2) (*emptypb.Empty, error) {
	if req.Id == 0 {
		return nil, errIncompleteRequest
	}

	_, err := ssa.dbMap.Exec(
		`UPDATE authz2 SET status = :deactivated WHERE id = :id and status IN (:valid,:pending)`,
		map[string]interface{}{
			"deactivated": statusUint(core.StatusDeactivated),
			"id":          req.Id,
			"valid":       statusUint(core.StatusValid),
			"pending":     statusUint(core.StatusPending),
		},
	)
	if err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

// NewOrder adds a new v2 style order to the database
func (ssa *SQLStorageAuthority) NewOrder(ctx context.Context, req *sapb.NewOrderRequest) (*corepb.Order, error) {
	output, err := db.WithTransaction(ctx, ssa.dbMap, func(txWithCtx db.Executor) (interface{}, error) {
		// Check new order request fields.
		if req.RegistrationID == 0 || req.Expires == 0 || len(req.Names) == 0 {
			return nil, errIncompleteRequest
		}

		order := &orderModel{
			RegistrationID: req.RegistrationID,
			Expires:        time.Unix(0, req.Expires),
			Created:        ssa.clk.Now(),
		}

		err := txWithCtx.Insert(order)
		if err != nil {
			return nil, err
		}

		for _, id := range req.V2Authorizations {
			otoa := &orderToAuthzModel{
				OrderID: order.ID,
				AuthzID: id,
			}
			err := txWithCtx.Insert(otoa)
			if err != nil {
				return nil, err
			}
		}

		for _, name := range req.Names {
			reqdName := &requestedNameModel{
				OrderID:      order.ID,
				ReversedName: ReverseName(name),
			}
			err := txWithCtx.Insert(reqdName)
			if err != nil {
				return nil, err
			}
		}

		// Add an FQDNSet entry for the order
		err = addOrderFQDNSet(txWithCtx, req.Names, order.ID, order.RegistrationID, order.Expires)
		if err != nil {
			return nil, err
		}

		return order, nil
	})
	if err != nil {
		return nil, err
	}
	var order *orderModel
	var ok bool
	if order, ok = output.(*orderModel); !ok {
		return nil, fmt.Errorf("shouldn't happen: casting error in NewOrder")
	}

	if features.Enabled(features.FasterNewOrdersRateLimit) {
		// Increment the order creation count
		err := addNewOrdersRateLimit(ctx, ssa.dbMap, req.RegistrationID, ssa.clk.Now().Truncate(time.Minute))
		if err != nil {
			return nil, err
		}
	}

	res := &corepb.Order{
		// Carry some fields over the from input new order request.
		RegistrationID:   req.RegistrationID,
		Expires:          req.Expires,
		Names:            req.Names,
		V2Authorizations: req.V2Authorizations,
		// Some fields were generated by the database transaction.
		Id:      order.ID,
		Created: order.Created.UnixNano(),
		// A new order is never processing because it can't have been finalized yet.
		BeganProcessing: false,
	}

	// Calculate the order status before returning it. Since it may have reused all
	// valid authorizations the order may be "born" in a ready status.
	status, err := ssa.statusForOrder(ctx, res)
	if err != nil {
		return nil, err
	}
	res.Status = status
	return res, nil
}

// NewOrderAndAuthzs adds the given authorizations to the database, adds their
// autogenerated IDs to the given order, and then adds the order to the db.
// This is done inside a single transaction to prevent situations where new
// authorizations are created, but then their corresponding order is never
// created, leading to "invisible" pending authorizations.
func (ssa *SQLStorageAuthority) NewOrderAndAuthzs(ctx context.Context, req *sapb.NewOrderAndAuthzsRequest) (*corepb.Order, error) {
	output, err := db.WithTransaction(ctx, ssa.dbMap, func(txWithCtx db.Executor) (interface{}, error) {
		// First, insert all of the new authorizations and record their IDs.
		newAuthzIDs := make([]int64, 0)
		if len(req.NewAuthzs) != 0 {
			inserter, err := db.NewMultiInserter("authz2", authzFields, "id")
			if err != nil {
				return nil, err
			}
			for _, authz := range req.NewAuthzs {
				if authz.Status != string(core.StatusPending) {
					return nil, berrors.InternalServerError("authorization must be pending")
				}
				am, err := authzPBToModel(authz)
				if err != nil {
					return nil, err
				}
				err = inserter.Add([]interface{}{
					am.ID,
					am.IdentifierType,
					am.IdentifierValue,
					am.RegistrationID,
					am.Status,
					am.Expires,
					am.Challenges,
					am.Attempted,
					am.AttemptedAt,
					am.Token,
					am.ValidationError,
					am.ValidationRecord,
				})
				if err != nil {
					return nil, err
				}
			}
			newAuthzIDs, err = inserter.Insert(txWithCtx)
			if err != nil {
				return nil, err
			}
		}

		// Second, insert the new order.
		order := &orderModel{
			RegistrationID: req.NewOrder.RegistrationID,
			Expires:        time.Unix(0, req.NewOrder.Expires),
			Created:        ssa.clk.Now(),
		}
		err := txWithCtx.Insert(order)
		if err != nil {
			return nil, err
		}

		// Third, insert all of the orderToAuthz relations.
		inserter, err := db.NewMultiInserter("orderToAuthz2", "orderID, authzID", "")
		if err != nil {
			return nil, err
		}
		for _, id := range req.NewOrder.V2Authorizations {
			err = inserter.Add([]interface{}{order.ID, id})
			if err != nil {
				return nil, err
			}
		}
		for _, id := range newAuthzIDs {
			err = inserter.Add([]interface{}{order.ID, id})
			if err != nil {
				return nil, err
			}
		}
		_, err = inserter.Insert(txWithCtx)
		if err != nil {
			return nil, err
		}

		// Fourth, insert all of the requestedNames.
		inserter, err = db.NewMultiInserter("requestedNames", "orderID, reversedName", "")
		if err != nil {
			return nil, err
		}
		for _, name := range req.NewOrder.Names {
			err = inserter.Add([]interface{}{order.ID, ReverseName(name)})
			if err != nil {
				return nil, err
			}
		}
		_, err = inserter.Insert(txWithCtx)
		if err != nil {
			return nil, err
		}

		// Fifth, insert the FQDNSet entry for the order.
		err = addOrderFQDNSet(txWithCtx, req.NewOrder.Names, order.ID, order.RegistrationID, order.Expires)
		if err != nil {
			return nil, err
		}

		// Finally, build the overall Order PB and return it.
		return &corepb.Order{
			// ID and Created were auto-populated on the order model when it was inserted.
			Id:      order.ID,
			Created: order.Created.UnixNano(),
			// These are carried over from the original request unchanged.
			RegistrationID: req.NewOrder.RegistrationID,
			Expires:        req.NewOrder.Expires,
			Names:          req.NewOrder.Names,
			// Have to combine the already-associated and newly-reacted authzs.
			V2Authorizations: append(req.NewOrder.V2Authorizations, newAuthzIDs...),
			// A new order is never processing because it can't be finalized yet.
			BeganProcessing: false,
		}, nil
	})
	if err != nil {
		return nil, err
	}

	order, ok := output.(*corepb.Order)
	if !ok {
		return nil, fmt.Errorf("casting error in NewOrderAndAuthzs")
	}

	if features.Enabled(features.FasterNewOrdersRateLimit) {
		// Increment the order creation count
		err := addNewOrdersRateLimit(ctx, ssa.dbMap, req.NewOrder.RegistrationID, ssa.clk.Now().Truncate(time.Minute))
		if err != nil {
			return nil, err
		}
	}

	// Calculate the order status before returning it. Since it may have reused all
	// valid authorizations the order may be "born" in a ready status.
	status, err := ssa.statusForOrder(ctx, order)
	if err != nil {
		return nil, err
	}
	order.Status = status

	return order, nil
}

// SetOrderProcessing updates an order from pending status to processing
// status by updating the `beganProcessing` field of the corresponding
// Order table row in the DB.
func (ssa *SQLStorageAuthority) SetOrderProcessing(ctx context.Context, req *sapb.OrderRequest) (*emptypb.Empty, error) {
	if req.Id == 0 {
		return nil, errIncompleteRequest
	}
	_, overallError := db.WithTransaction(ctx, ssa.dbMap, func(txWithCtx db.Executor) (interface{}, error) {
		result, err := txWithCtx.Exec(`
		UPDATE orders
		SET beganProcessing = ?
		WHERE id = ?
		AND beganProcessing = ?`,
			true,
			req.Id,
			false)
		if err != nil {
			return nil, berrors.InternalServerError("error updating order to beganProcessing status")
		}

		n, err := result.RowsAffected()
		if err != nil || n == 0 {
			return nil, berrors.OrderNotReadyError("Order was already processing. This may indicate your client finalized the same order multiple times, possibly due to a client bug.")
		}

		return nil, nil
	})
	if overallError != nil {
		return nil, overallError
	}
	return &emptypb.Empty{}, nil
}

// SetOrderError updates a provided Order's error field.
func (ssa *SQLStorageAuthority) SetOrderError(ctx context.Context, req *sapb.SetOrderErrorRequest) (*emptypb.Empty, error) {
	if req.Id == 0 || req.Error == nil {
		return nil, errIncompleteRequest
	}
	_, overallError := db.WithTransaction(ctx, ssa.dbMap, func(txWithCtx db.Executor) (interface{}, error) {
		om, err := orderToModel(&corepb.Order{
			Id:    req.Id,
			Error: req.Error,
		})
		if err != nil {
			return nil, err
		}

		result, err := txWithCtx.Exec(`
		UPDATE orders
		SET error = ?
		WHERE id = ?`,
			om.Error,
			om.ID)
		if err != nil {
			return nil, berrors.InternalServerError("error updating order error field")
		}

		n, err := result.RowsAffected()
		if err != nil || n == 0 {
			return nil, berrors.InternalServerError("no order updated with new error field")
		}

		return nil, nil
	})
	if overallError != nil {
		return nil, overallError
	}
	return &emptypb.Empty{}, nil
}

// FinalizeOrder finalizes a provided *corepb.Order by persisting the
// CertificateSerial and a valid status to the database. No fields other than
// CertificateSerial and the order ID on the provided order are processed (e.g.
// this is not a generic update RPC).
func (ssa *SQLStorageAuthority) FinalizeOrder(ctx context.Context, req *sapb.FinalizeOrderRequest) (*emptypb.Empty, error) {
	if req.Id == 0 || req.CertificateSerial == "" {
		return nil, errIncompleteRequest
	}
	_, overallError := db.WithTransaction(ctx, ssa.dbMap, func(txWithCtx db.Executor) (interface{}, error) {
		result, err := txWithCtx.Exec(`
		UPDATE orders
		SET certificateSerial = ?
		WHERE id = ? AND
		beganProcessing = true`,
			req.CertificateSerial,
			req.Id)
		if err != nil {
			return nil, berrors.InternalServerError("error updating order for finalization")
		}

		n, err := result.RowsAffected()
		if err != nil || n == 0 {
			return nil, berrors.InternalServerError("no order updated for finalization")
		}

		// Delete the orderFQDNSet row for the order now that it has been finalized.
		// We use this table for order reuse and should not reuse a finalized order.
		err = deleteOrderFQDNSet(txWithCtx, req.Id)
		if err != nil {
			return nil, err
		}

		return nil, nil
	})
	if overallError != nil {
		return nil, overallError
	}
	return &emptypb.Empty{}, nil
}

// authzForOrder retrieves the authorization IDs for an order.
func (ssa *SQLStorageAuthority) authzForOrder(ctx context.Context, orderID int64) ([]int64, error) {
	var v2IDs []int64
	_, err := ssa.dbMap.WithContext(ctx).Select(
		&v2IDs,
		"SELECT authzID FROM orderToAuthz2 WHERE orderID = ?",
		orderID,
	)
	return v2IDs, err
}

// namesForOrder finds all of the requested names associated with an order. The
// names are returned in their reversed form (see `sa.ReverseName`).
func (ssa *SQLStorageAuthority) namesForOrder(ctx context.Context, orderID int64) ([]string, error) {
	var reversedNames []string
	_, err := ssa.dbMap.WithContext(ctx).Select(
		&reversedNames,
		`SELECT reversedName
	   FROM requestedNames
	   WHERE orderID = ?`,
		orderID)
	if err != nil {
		return nil, err
	}
	return reversedNames, nil
}

// GetOrder is used to retrieve an already existing order object
func (ssa *SQLStorageAuthority) GetOrder(ctx context.Context, req *sapb.OrderRequest) (*corepb.Order, error) {
	if req == nil || req.Id == 0 {
		return nil, errIncompleteRequest
	}

	omObj, err := ssa.dbMap.WithContext(ctx).Get(orderModel{}, req.Id)
	if err != nil {
		if db.IsNoRows(err) {
			return nil, berrors.NotFoundError("no order found for ID %d", req.Id)
		}
		return nil, err
	}
	if omObj == nil {
		return nil, berrors.NotFoundError("no order found for ID %d", req.Id)
	}
	order, err := modelToOrder(omObj.(*orderModel))
	if err != nil {
		return nil, err
	}
	orderExp := time.Unix(0, order.Expires)
	if orderExp.Before(ssa.clk.Now()) {
		return nil, berrors.NotFoundError("no order found for ID %d", req.Id)
	}

	v2AuthzIDs, err := ssa.authzForOrder(ctx, order.Id)
	if err != nil {
		return nil, err
	}
	order.V2Authorizations = v2AuthzIDs

	names, err := ssa.namesForOrder(ctx, order.Id)
	if err != nil {
		return nil, err
	}
	// The requested names are stored reversed to improve indexing performance. We
	// need to reverse the reversed names here before giving them back to the
	// caller.
	reversedNames := make([]string, len(names))
	for i, n := range names {
		reversedNames[i] = ReverseName(n)
	}
	order.Names = reversedNames

	// Calculate the status for the order
	status, err := ssa.statusForOrder(ctx, order)
	if err != nil {
		return nil, err
	}
	order.Status = status

	return order, nil
}

// statusForOrder examines the status of a provided order's authorizations to
// determine what the overall status of the order should be. In summary:
//   * If the order has an error, the order is invalid
//   * If any of the order's authorizations are in any state other than
//     valid or pending, the order is invalid.
//   * If any of the order's authorizations are pending, the order is pending.
//   * If all of the order's authorizations are valid, and there is
//     a certificate serial, the order is valid.
//   * If all of the order's authorizations are valid, and we have began
//     processing, but there is no certificate serial, the order is processing.
//   * If all of the order's authorizations are valid, and we haven't begun
//     processing, then the order is status ready.
// An error is returned for any other case.
func (ssa *SQLStorageAuthority) statusForOrder(ctx context.Context, order *corepb.Order) (string, error) {
	// Without any further work we know an order with an error is invalid
	if order.Error != nil {
		return string(core.StatusInvalid), nil
	}

	// If the order is expired the status is invalid and we don't need to get
	// order authorizations. Its important to exit early in this case because an
	// order that references an expired authorization will be itself have been
	// expired (because we match the order expiry to the associated authz expiries
	// in ra.NewOrder), and expired authorizations may be purged from the DB.
	// Because of this purging fetching the authz's for an expired order may
	// return fewer authz objects than expected, triggering a 500 error response.
	orderExpiry := time.Unix(0, order.Expires)
	if orderExpiry.Before(ssa.clk.Now()) {
		return string(core.StatusInvalid), nil
	}

	// Get the full Authorization objects for the order
	authzValidityInfo, err := ssa.getAuthorizationStatuses(ctx, order.V2Authorizations)
	// If there was an error getting the authorizations, return it immediately
	if err != nil {
		return "", err
	}

	// If getAuthorizationStatuses returned a different number of authorization
	// objects than the order's slice of authorization IDs something has gone
	// wrong worth raising an internal error about.
	if len(authzValidityInfo) != len(order.V2Authorizations) {
		return "", berrors.InternalServerError(
			"getAuthorizationStatuses returned the wrong number of authorization statuses "+
				"(%d vs expected %d) for order %d",
			len(authzValidityInfo), len(order.V2Authorizations), order.Id)
	}

	// Keep a count of the authorizations seen
	pendingAuthzs := 0
	validAuthzs := 0
	otherAuthzs := 0
	expiredAuthzs := 0

	// Loop over each of the order's authorization objects to examine the authz status
	for _, info := range authzValidityInfo {
		switch core.AcmeStatus(info.Status) {
		case core.StatusPending:
			pendingAuthzs++
		case core.StatusValid:
			validAuthzs++
		case core.StatusInvalid:
			otherAuthzs++
		case core.StatusDeactivated:
			otherAuthzs++
		case core.StatusRevoked:
			otherAuthzs++
		default:
			return "", berrors.InternalServerError(
				"Order is in an invalid state. Authz has invalid status %s",
				info.Status)
		}
		if info.Expires.Before(ssa.clk.Now()) {
			expiredAuthzs++
		}
	}

	// An order is invalid if **any** of its authzs are invalid, deactivated,
	// revoked, or expired, see https://tools.ietf.org/html/rfc8555#section-7.1.6
	if otherAuthzs > 0 || expiredAuthzs > 0 {
		return string(core.StatusInvalid), nil
	}
	// An order is pending if **any** of its authzs are pending
	if pendingAuthzs > 0 {
		return string(core.StatusPending), nil
	}

	// An order is fully authorized if it has valid authzs for each of the order
	// names
	fullyAuthorized := len(order.Names) == validAuthzs

	// If the order isn't fully authorized we've encountered an internal error:
	// Above we checked for any invalid or pending authzs and should have returned
	// early. Somehow we made it this far but also don't have the correct number
	// of valid authzs.
	if !fullyAuthorized {
		return "", berrors.InternalServerError(
			"Order has the incorrect number of valid authorizations & no pending, " +
				"deactivated or invalid authorizations")
	}

	// If the order is fully authorized and the certificate serial is set then the
	// order is valid
	if fullyAuthorized && order.CertificateSerial != "" {
		return string(core.StatusValid), nil
	}

	// If the order is fully authorized, and we have began processing it, then the
	// order is processing.
	if fullyAuthorized && order.BeganProcessing {
		return string(core.StatusProcessing), nil
	}

	if fullyAuthorized && !order.BeganProcessing {
		return string(core.StatusReady), nil
	}

	return "", berrors.InternalServerError(
		"Order %d is in an invalid state. No state known for this order's "+
			"authorizations", order.Id)
}

type authzValidity struct {
	Status  string
	Expires time.Time
}

func (ssa *SQLStorageAuthority) getAuthorizationStatuses(ctx context.Context, ids []int64) ([]authzValidity, error) {
	var qmarks []string
	var params []interface{}
	for _, id := range ids {
		qmarks = append(qmarks, "?")
		params = append(params, id)
	}
	var validityInfo []struct {
		Status  uint8
		Expires time.Time
	}
	_, err := ssa.dbMap.WithContext(ctx).Select(
		&validityInfo,
		fmt.Sprintf("SELECT status, expires FROM authz2 WHERE id IN (%s)", strings.Join(qmarks, ",")),
		params...,
	)
	if err != nil {
		return nil, err
	}

	allAuthzValidity := make([]authzValidity, len(validityInfo))
	for i, info := range validityInfo {
		allAuthzValidity[i] = authzValidity{
			Status:  string(uintToStatus[info.Status]),
			Expires: info.Expires,
		}
	}
	return allAuthzValidity, nil
}

// GetOrderForNames tries to find a **pending** or **ready** order with the
// exact set of names requested, associated with the given accountID. Only
// unexpired orders are considered. If no order meeting these requirements is
// found a nil corepb.Order pointer is returned.
func (ssa *SQLStorageAuthority) GetOrderForNames(
	ctx context.Context,
	req *sapb.GetOrderForNamesRequest) (*corepb.Order, error) {

	if req.AcctID == 0 || len(req.Names) == 0 {
		return nil, errIncompleteRequest
	}

	// Hash the names requested for lookup in the orderFqdnSets table
	fqdnHash := HashNames(req.Names)

	// Find a possibly-suitable order. We don't include the account ID or order
	// status in this query because there's no index that includes those, so
	// including them could require the DB to scan extra rows.
	// Instead, we select one unexpired order that matches the fqdnSet. If
	// that order doesn't match the account ID or status we need, just return
	// nothing. We use `ORDER BY expires ASC` because the index on
	// (setHash, expires) is in ASC order. DESC would be slightly nicer from a
	// user experience perspective but would be slow when there are many entries
	// to sort.
	// This approach works fine because in most cases there's only one account
	// issuing for a given name. If there are other accounts issuing for the same
	// name, it just means order reuse happens less often.
	var result struct {
		OrderID        int64
		RegistrationID int64
	}
	var err error
	err = ssa.dbMap.WithContext(ctx).SelectOne(&result, `
					SELECT orderID, registrationID
					FROM orderFqdnSets
					WHERE setHash = ?
					AND expires > ?
					ORDER BY expires ASC
					LIMIT 1`,
		fqdnHash, ssa.clk.Now())

	if db.IsNoRows(err) {
		return nil, berrors.NotFoundError("no order matching request found")
	} else if err != nil {
		return nil, err
	}

	if result.RegistrationID != req.AcctID {
		return nil, berrors.NotFoundError("no order matching request found")
	}

	// Get the order
	order, err := ssa.GetOrder(ctx, &sapb.OrderRequest{Id: result.OrderID})
	if err != nil {
		return nil, err
	}
	// Only return a pending or ready order
	if order.Status != string(core.StatusPending) &&
		order.Status != string(core.StatusReady) {
		return nil, berrors.NotFoundError("no order matching request found")
	}
	return order, nil
}

func AuthzMapToPB(m map[string]*core.Authorization) (*sapb.Authorizations, error) {
	resp := &sapb.Authorizations{}
	for k, v := range m {
		authzPB, err := bgrpc.AuthzToPB(*v)
		if err != nil {
			return nil, err
		}
		resp.Authz = append(resp.Authz, &sapb.Authorizations_MapElement{Domain: k, Authz: authzPB})
	}
	return resp, nil
}

// NewAuthorizations2 adds a set of new style authorizations to the database and
// returns either the IDs of the authorizations or an error.
// TODO(#5816): Consider removing this method, as it has no callers.
func (ssa *SQLStorageAuthority) NewAuthorizations2(ctx context.Context, req *sapb.AddPendingAuthorizationsRequest) (*sapb.Authorization2IDs, error) {
	if len(req.Authz) == 0 {
		return nil, errIncompleteRequest
	}

	ids := &sapb.Authorization2IDs{}
	var queryArgs []interface{}
	var questionsBuf strings.Builder

	for _, authz := range req.Authz {
		if authz.Status != string(core.StatusPending) {
			return nil, berrors.InternalServerError("authorization must be pending")
		}
		am, err := authzPBToModel(authz)
		if err != nil {
			return nil, err
		}

		// Each authz needs a (?,?...), in the VALUES block. We need one
		// for each element in the authzFields string.
		fmt.Fprint(&questionsBuf, "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?),")

		// The query arguments must follow the order of the authzFields string.
		queryArgs = append(queryArgs,
			am.ID,
			am.IdentifierType,
			am.IdentifierValue,
			am.RegistrationID,
			am.Status,
			am.Expires,
			am.Challenges,
			am.Attempted,
			am.AttemptedAt,
			am.Token,
			am.ValidationError,
			am.ValidationRecord,
		)
	}

	// At this point, the VALUES block question-string has a trailing comma, we need
	// to remove it to make sure we're valid SQL.
	questionsTrimmed := strings.TrimRight(questionsBuf.String(), ",")
	query := fmt.Sprintf("INSERT INTO authz2 (%s) VALUES %s RETURNING id;", authzFields, questionsTrimmed)

	rows, err := ssa.dbMap.Db.QueryContext(ctx, query, queryArgs...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var idField int64
		err = rows.Scan(&idField)
		if err != nil {
			rows.Close()
			return nil, err
		}
		ids.Ids = append(ids.Ids, idField)
	}

	// Ensure the query wasn't interrupted before it could complete.
	err = rows.Close()
	if err != nil {
		return nil, err
	}
	return ids, nil
}

// GetAuthorization2 returns the authz2 style authorization identified by the provided ID or an error.
// If no authorization is found matching the ID a berrors.NotFound type error is returned.
func (ssa *SQLStorageAuthority) GetAuthorization2(ctx context.Context, req *sapb.AuthorizationID2) (*corepb.Authorization, error) {
	if req.Id == 0 {
		return nil, errIncompleteRequest
	}
	obj, err := ssa.dbMap.Get(authzModel{}, req.Id)
	if err != nil {
		return nil, err
	}
	if obj == nil {
		return nil, berrors.NotFoundError("authorization %d not found", req.Id)
	}
	return modelToAuthzPB(*(obj.(*authzModel)))
}

// authzModelMapToPB converts a mapping of domain name to authzModels into a
// protobuf authorizations map
func authzModelMapToPB(m map[string]authzModel) (*sapb.Authorizations, error) {
	resp := &sapb.Authorizations{}
	for k, v := range m {
		authzPB, err := modelToAuthzPB(v)
		if err != nil {
			return nil, err
		}
		resp.Authz = append(resp.Authz, &sapb.Authorizations_MapElement{Domain: k, Authz: authzPB})
	}
	return resp, nil
}

// GetAuthorizations2 returns any valid or pending authorizations that exist for the list of domains
// provided. If both a valid and pending authorization exist only the valid one will be returned.
func (ssa *SQLStorageAuthority) GetAuthorizations2(ctx context.Context, req *sapb.GetAuthorizationsRequest) (*sapb.Authorizations, error) {
	if len(req.Domains) == 0 || req.RegistrationID == 0 || req.Now == 0 {
		return nil, errIncompleteRequest
	}
	var authzModels []authzModel
	params := []interface{}{
		req.RegistrationID,
		statusUint(core.StatusValid),
		statusUint(core.StatusPending),
		time.Unix(0, req.Now),
		identifierTypeToUint[string(identifier.DNS)],
	}

	useIndex := ""
	if features.Enabled(features.GetAuthzUseIndex) {
		useIndex = "USE INDEX (regID_identifier_status_expires_idx)"
	}

	qmarks := make([]string, len(req.Domains))
	for i, n := range req.Domains {
		qmarks[i] = "?"
		params = append(params, n)
	}

	query := fmt.Sprintf(
		`SELECT %s FROM authz2
			%s
			WHERE registrationID = ? AND
			status IN (?,?) AND
			expires > ? AND
			identifierType = ? AND
			identifierValue IN (%s)`,
		authzFields,
		useIndex,
		strings.Join(qmarks, ","),
	)

	dbMap := ssa.dbMap
	if features.Enabled(features.GetAuthzReadOnly) {
		dbMap = ssa.dbReadOnlyMap
	}
	_, err := dbMap.Select(
		&authzModels,
		query,
		params...,
	)
	if err != nil {
		return nil, err
	}

	if len(authzModels) == 0 {
		return &sapb.Authorizations{}, nil
	}

	authzModelMap := make(map[string]authzModel)
	for _, am := range authzModels {
		existing, present := authzModelMap[am.IdentifierValue]
		if !present || uintToStatus[existing.Status] == core.StatusPending && uintToStatus[am.Status] == core.StatusValid {
			authzModelMap[am.IdentifierValue] = am
		}
	}

	return authzModelMapToPB(authzModelMap)
}

// FinalizeAuthorization2 moves a pending authorization to either the valid or invalid status. If
// the authorization is being moved to invalid the validationError field must be set. If the
// authorization is being moved to valid the validationRecord and expires fields must be set.
func (ssa *SQLStorageAuthority) FinalizeAuthorization2(ctx context.Context, req *sapb.FinalizeAuthorizationRequest) (*emptypb.Empty, error) {
	if req.Status == "" || req.Attempted == "" || req.Expires == 0 || req.Id == 0 {
		return nil, errIncompleteRequest
	}

	if req.Status != string(core.StatusValid) && req.Status != string(core.StatusInvalid) {
		return nil, berrors.InternalServerError("authorization must have status valid or invalid")
	}
	query := `UPDATE authz2 SET
		status = :status,
		attempted = :attempted,
		attemptedAt = :attemptedAt,
		validationRecord = :validationRecord,
		validationError = :validationError,
		expires = :expires
		WHERE id = :id AND status = :pending`
	var validationRecords []core.ValidationRecord
	for _, recordPB := range req.ValidationRecords {
		record, err := bgrpc.PBToValidationRecord(recordPB)
		if err != nil {
			return nil, err
		}
		validationRecords = append(validationRecords, record)
	}
	vrJSON, err := json.Marshal(validationRecords)
	if err != nil {
		return nil, err
	}
	var veJSON []byte
	if req.ValidationError != nil {
		validationError, err := bgrpc.PBToProblemDetails(req.ValidationError)
		if err != nil {
			return nil, err
		}
		j, err := json.Marshal(validationError)
		if err != nil {
			return nil, err
		}
		veJSON = j
	}
	// Check to see if the AttemptedAt time is non zero and convert to
	// *time.Time if so. If it is zero, leave nil and don't convert. Keep
	// the the database attemptedAt field Null instead of
	// 1970-01-01 00:00:00.
	var attemptedTime *time.Time
	if req.AttemptedAt != 0 {
		val := time.Unix(0, req.AttemptedAt).UTC()
		attemptedTime = &val
	}
	params := map[string]interface{}{
		"status":           statusToUint[core.AcmeStatus(req.Status)],
		"attempted":        challTypeToUint[req.Attempted],
		"attemptedAt":      attemptedTime,
		"validationRecord": vrJSON,
		"id":               req.Id,
		"pending":          statusUint(core.StatusPending),
		"expires":          time.Unix(0, req.Expires).UTC(),
		// if req.ValidationError is nil veJSON should also be nil
		// which should result in a NULL field
		"validationError": veJSON,
	}

	res, err := ssa.dbMap.Exec(query, params)
	if err != nil {
		return nil, err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return nil, err
	}
	if rows == 0 {
		return nil, berrors.NotFoundError("authorization with id %d not found", req.Id)
	} else if rows > 1 {
		return nil, berrors.InternalServerError("multiple rows updated for authorization id %d", req.Id)
	}
	return &emptypb.Empty{}, nil
}

// RevokeCertificate stores revocation information about a certificate. It will only store this
// information if the certificate is not already marked as revoked.
func (ssa *SQLStorageAuthority) RevokeCertificate(ctx context.Context, req *sapb.RevokeCertificateRequest) (*emptypb.Empty, error) {
	if req.Serial == "" || req.Date == 0 || req.Response == nil {
		return nil, errIncompleteRequest
	}
	revokedDate := time.Unix(0, req.Date)
	res, err := ssa.dbMap.Exec(
		`UPDATE certificateStatus SET
				status = ?,
				revokedReason = ?,
				revokedDate = ?,
				ocspLastUpdated = ?,
				ocspResponse = ?
			WHERE serial = ? AND status != ?`,
		string(core.OCSPStatusRevoked),
		revocation.Reason(req.Reason),
		revokedDate,
		revokedDate,
		req.Response,
		req.Serial,
		string(core.OCSPStatusRevoked),
	)
	if err != nil {
		return nil, err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return nil, err
	}
	if rows == 0 {
		return nil, berrors.AlreadyRevokedError("no certificate with serial %s and status other than %s", req.Serial, string(core.OCSPStatusRevoked))
	}

	return &emptypb.Empty{}, nil
}

// UpdateRevokedCertificate stores new revocation information about an
// already-revoked certificate. It will only store this information if the
// cert is already revoked, if the new revocation reason is `KeyCompromise`,
// and if the revokedDate is identical to the current revokedDate.
func (ssa *SQLStorageAuthority) UpdateRevokedCertificate(ctx context.Context, req *sapb.RevokeCertificateRequest) (*emptypb.Empty, error) {
	if req.Serial == "" || req.Date == 0 || req.Backdate == 0 || req.Response == nil {
		return nil, errIncompleteRequest
	}
	if req.Reason != ocsp.KeyCompromise {
		return nil, fmt.Errorf("cannot update revocation for any reason other than keyCompromise (1); got: %d", req.Reason)
	}
	thisUpdate := time.Unix(0, req.Date)
	revokedDate := time.Unix(0, req.Backdate)
	res, err := ssa.dbMap.Exec(
		`UPDATE certificateStatus SET
				revokedReason = ?,
				ocspLastUpdated = ?,
				ocspResponse = ?
			WHERE serial = ? AND status = ? AND revokedReason != ? AND revokedDate = ?`,
		revocation.Reason(ocsp.KeyCompromise),
		thisUpdate,
		req.Response,
		req.Serial,
		string(core.OCSPStatusRevoked),
		revocation.Reason(ocsp.KeyCompromise),
		revokedDate,
	)
	if err != nil {
		return nil, err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return nil, err
	}
	if rows == 0 {
		// InternalServerError because we expected this certificate status to exist,
		// to already be revoked for a different reason, and to have a matching date.
		return nil, berrors.InternalServerError("no certificate with serial %s and revoked reason other than keyCompromise", req.Serial)
	}

	return &emptypb.Empty{}, nil
}

// GetPendingAuthorization2 returns the most recent Pending authorization with
// the given identifier, if available. This method only supports DNS identifier types.
// TODO(#5816): Consider removing this method, as it has no callers.
func (ssa *SQLStorageAuthority) GetPendingAuthorization2(ctx context.Context, req *sapb.GetPendingAuthorizationRequest) (*corepb.Authorization, error) {
	if req.RegistrationID == 0 || req.IdentifierValue == "" || req.ValidUntil == 0 {
		return nil, errIncompleteRequest
	}
	var am authzModel
	err := ssa.dbMap.WithContext(ctx).SelectOne(
		&am,
		fmt.Sprintf(`SELECT %s FROM authz2 WHERE
			registrationID = :regID AND
			status = :status AND
			expires > :validUntil AND
			identifierType = :dnsType AND
			identifierValue = :ident
			ORDER BY expires ASC
			LIMIT 1 `, authzFields),
		map[string]interface{}{
			"regID":      req.RegistrationID,
			"status":     statusUint(core.StatusPending),
			"validUntil": time.Unix(0, req.ValidUntil),
			"dnsType":    identifierTypeToUint[string(identifier.DNS)],
			"ident":      req.IdentifierValue,
		},
	)
	if err != nil {
		if db.IsNoRows(err) {
			return nil, berrors.NotFoundError("pending authz not found")
		}
		return nil, err
	}
	return modelToAuthzPB(am)
}

// CountPendingAuthorizations2 returns the number of pending, unexpired authorizations
// for the given registration.
func (ssa *SQLStorageAuthority) CountPendingAuthorizations2(ctx context.Context, req *sapb.RegistrationID) (*sapb.Count, error) {
	if req.Id == 0 {
		return nil, errIncompleteRequest
	}

	var count int64
	err := ssa.dbReadOnlyMap.WithContext(ctx).SelectOne(&count,
		`SELECT COUNT(1) FROM authz2 WHERE
		registrationID = :regID AND
		expires > :expires AND
		status = :status`,
		map[string]interface{}{
			"regID":   req.Id,
			"expires": ssa.clk.Now(),
			"status":  statusUint(core.StatusPending),
		},
	)
	if err != nil {
		return nil, err
	}
	return &sapb.Count{Count: count}, nil
}

// GetValidOrderAuthorizations2 is used to find the valid, unexpired authorizations
// associated with a specific order and account ID.
func (ssa *SQLStorageAuthority) GetValidOrderAuthorizations2(ctx context.Context, req *sapb.GetValidOrderAuthorizationsRequest) (*sapb.Authorizations, error) {
	if req.AcctID == 0 || req.Id == 0 {
		return nil, errIncompleteRequest
	}

	var ams []authzModel
	_, err := ssa.dbMap.WithContext(ctx).Select(
		&ams,
		fmt.Sprintf(`SELECT %s FROM authz2
			LEFT JOIN orderToAuthz2 ON authz2.ID = orderToAuthz2.authzID
			WHERE authz2.registrationID = :regID AND
			authz2.expires > :expires AND
			authz2.status = :status AND
			orderToAuthz2.orderID = :orderID`,
			authzFields,
		),
		map[string]interface{}{
			"regID":   req.AcctID,
			"expires": ssa.clk.Now(),
			"status":  statusUint(core.StatusValid),
			"orderID": req.Id,
		},
	)
	if err != nil {
		return nil, err
	}

	byName := make(map[string]authzModel)
	for _, am := range ams {
		if uintToIdentifierType[am.IdentifierType] != string(identifier.DNS) {
			return nil, fmt.Errorf("unknown identifier type: %q on authz id %d", am.IdentifierType, am.ID)
		}
		existing, present := byName[am.IdentifierValue]
		if !present || am.Expires.After(existing.Expires) {
			byName[am.IdentifierValue] = am
		}
	}

	return authzModelMapToPB(byName)
}

// CountInvalidAuthorizations2 counts invalid authorizations for a user expiring
// in a given time range. This method only supports DNS identifier types.
func (ssa *SQLStorageAuthority) CountInvalidAuthorizations2(ctx context.Context, req *sapb.CountInvalidAuthorizationsRequest) (*sapb.Count, error) {
	if req.RegistrationID == 0 || req.Hostname == "" || req.Range.Earliest == 0 || req.Range.Latest == 0 {
		return nil, errIncompleteRequest
	}

	var count int64
	err := ssa.dbReadOnlyMap.WithContext(ctx).SelectOne(
		&count,
		`SELECT COUNT(1) FROM authz2 WHERE
		registrationID = :regID AND
		status = :status AND
		expires > :expiresEarliest AND
		expires <= :expiresLatest AND
		identifierType = :dnsType AND
		identifierValue = :ident`,
		map[string]interface{}{
			"regID":           req.RegistrationID,
			"dnsType":         identifierTypeToUint[string(identifier.DNS)],
			"ident":           req.Hostname,
			"expiresEarliest": time.Unix(0, req.Range.Earliest),
			"expiresLatest":   time.Unix(0, req.Range.Latest),
			"status":          statusUint(core.StatusInvalid),
		},
	)
	if err != nil {
		return nil, err
	}
	return &sapb.Count{Count: count}, nil
}

// GetValidAuthorizations2 returns the latest authorization for all
// domain names that the account has authorizations for. This method is
// intended to deprecate GetValidAuthorizations. This method only supports
// DNS identifier types.
func (ssa *SQLStorageAuthority) GetValidAuthorizations2(ctx context.Context, req *sapb.GetValidAuthorizationsRequest) (*sapb.Authorizations, error) {
	if len(req.Domains) == 0 || req.RegistrationID == 0 || req.Now == 0 {
		return nil, errIncompleteRequest
	}

	var authzModels []authzModel
	params := []interface{}{
		req.RegistrationID,
		statusUint(core.StatusValid),
		time.Unix(0, req.Now),
		identifierTypeToUint[string(identifier.DNS)],
	}
	qmarks := make([]string, len(req.Domains))
	for i, n := range req.Domains {
		qmarks[i] = "?"
		params = append(params, n)
	}
	_, err := ssa.dbMap.Select(
		&authzModels,
		fmt.Sprintf(
			`SELECT %s FROM authz2 WHERE
			registrationID = ? AND
			status = ? AND
			expires > ? AND
			identifierType = ? AND
			identifierValue IN (%s)`,
			authzFields,
			strings.Join(qmarks, ","),
		),
		params...,
	)
	if err != nil {
		return nil, err
	}

	authzMap := make(map[string]authzModel, len(authzModels))
	for _, am := range authzModels {
		// Only allow DNS identifiers
		if uintToIdentifierType[am.IdentifierType] != string(identifier.DNS) {
			continue
		}
		// If there is an existing authorization in the map only replace it with one
		// which has a later expiry.
		if existing, present := authzMap[am.IdentifierValue]; present && am.Expires.Before(existing.Expires) {
			continue
		}
		authzMap[am.IdentifierValue] = am
	}
	return authzModelMapToPB(authzMap)
}

func addKeyHash(db db.Inserter, cert *x509.Certificate) error {
	if cert.RawSubjectPublicKeyInfo == nil {
		return errors.New("certificate has a nil RawSubjectPublicKeyInfo")
	}
	h := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	khm := &keyHashModel{
		KeyHash:      h[:],
		CertNotAfter: cert.NotAfter,
		CertSerial:   core.SerialToString(cert.SerialNumber),
	}
	return db.Insert(khm)
}

var blockedKeysColumns = "keyHash, added, source, comment"

// AddBlockedKey adds a key hash to the blockedKeys table
func (ssa *SQLStorageAuthority) AddBlockedKey(ctx context.Context, req *sapb.AddBlockedKeyRequest) (*emptypb.Empty, error) {
	if core.IsAnyNilOrZero(req.KeyHash, req.Added, req.Source) {
		return nil, errIncompleteRequest
	}
	sourceInt, ok := stringToSourceInt[req.Source]
	if !ok {
		return nil, errors.New("unknown source")
	}
	cols, qs := blockedKeysColumns, "?, ?, ?, ?"
	vals := []interface{}{
		req.KeyHash,
		time.Unix(0, req.Added),
		sourceInt,
		req.Comment,
	}
	if features.Enabled(features.StoreRevokerInfo) && req.RevokedBy != 0 {
		cols += ", revokedBy"
		qs += ", ?"
		vals = append(vals, req.RevokedBy)
	}
	_, err := ssa.dbMap.Exec(
		fmt.Sprintf("INSERT INTO blockedKeys (%s) VALUES (%s)", cols, qs),
		vals...,
	)
	if err != nil {
		if db.IsDuplicate(err) {
			// Ignore duplicate inserts so multiple certs with the same key can
			// be revoked.
			return &emptypb.Empty{}, nil
		}
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

// KeyBlocked checks if a key, indicated by a hash, is present in the blockedKeys table
func (ssa *SQLStorageAuthority) KeyBlocked(ctx context.Context, req *sapb.KeyBlockedRequest) (*sapb.Exists, error) {
	if req == nil || req.KeyHash == nil {
		return nil, errIncompleteRequest
	}

	var id int64
	err := ssa.dbMap.SelectOne(&id, `SELECT ID FROM blockedKeys WHERE keyHash = ?`, req.KeyHash)
	if err != nil {
		if db.IsNoRows(err) {
			return &sapb.Exists{Exists: false}, nil
		}
		return nil, err
	}

	return &sapb.Exists{Exists: true}, nil
}

// IncidentsForSerial queries each active incident table and returns every
// incident that currently impacts `req.Serial`.
func (ssa *SQLStorageAuthority) IncidentsForSerial(ctx context.Context, req *sapb.Serial) ([]sapb.Incident, error) {
	if req == nil {
		return nil, errIncompleteRequest
	}

	var activeIncidents []incidentModel
	_, err := ssa.dbMap.Select(&activeIncidents, `SELECT * FROM incidents WHERE enabled = 1`)
	if err != nil {
		if db.IsNoRows(err) {
			return nil, berrors.NotFoundError("no active incidents found")
		}
		return nil, err
	}

	var incidentsForSerial []sapb.Incident
	for _, i := range activeIncidents {
		var count int
		err := ssa.dbMap.SelectOne(&count, fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE serial = ?",
			i.SerialTable), req.Serial)
		if err != nil {
			if db.IsNoRows(err) {
				continue
			}
			return nil, err
		}
		if count > 0 {
			incidentsForSerial = append(incidentsForSerial, incidentModelToPB(i))
		}

	}
	if len(incidentsForSerial) == 0 {
		return nil, berrors.NotFoundError("no active incidents found for serial %q", req.Serial)
	}
	return incidentsForSerial, nil
}

// SerialsForIncident queries the provided incident table and returns the
// resulting rows as a stream of `*sapb.IncidentSerial`s. An `io.EOF` error
// signals that there are no more serials to send. If the incident table in
// question contains zero rows, only an `io.EOF` error is returned.
func (ssa *SQLStorageAuthority) SerialsForIncident(req *sapb.SerialsForIncidentRequest, stream sapb.StorageAuthority_SerialsForIncidentServer) error {
	if req.IncidentTable == "" {
		return errIncompleteRequest
	}

	// Check that `req.IncidentTable` is a valid incident table name.
	if !validIncidentTableRegexp.MatchString(req.IncidentTable) {
		return fmt.Errorf("malformed table name %q", req.IncidentTable)
	}

	selector, err := db.NewMappedSelector[incidentSerialModel](ssa.dbReadOnlyMap)
	if err != nil {
		return fmt.Errorf("initializing db map: %w", err)
	}

	rows, err := selector.QueryFrom(stream.Context(), req.IncidentTable, "")
	if err != nil {
		return fmt.Errorf("starting db query: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		// Scan the row into the model. Note: the fields must be passed in the
		// same order as the columns returned by the query above.
		ism, err := rows.Get()
		if err != nil {
			return err
		}

		err = stream.Send(
			&sapb.IncidentSerial{
				Serial:         ism.Serial,
				RegistrationID: ism.RegistrationID,
				OrderID:        ism.OrderID,
				LastNoticeSent: ism.LastNoticeSent.UnixNano(),
			})
		if err != nil {
			return err
		}
	}

	err = rows.Err()
	if err != nil {
		return err
	}
	return nil
}

// GetRevokedCerts gets a request specifying an issuer and a period of time,
// and writes to the output stream the set of all certificates issued by that
// issuer which expire during that period of time and which have been revoked.
// The starting timestamp is treated as inclusive (certs with exactly that
// notAfter date are included), but the ending timestamp is exclusive (certs
// with exactly that notAfter date are *not* included).
func (ssa *SQLStorageAuthority) GetRevokedCerts(req *sapb.GetRevokedCertsRequest, stream sapb.StorageAuthority_GetRevokedCertsServer) error {
	atTime := time.Unix(0, req.RevokedBefore)

	clauses := `
		WHERE notAfter >= ?
		AND notAfter < ?
		AND issuerID = ?
		AND status = ?`
	params := []interface{}{
		time.Unix(0, req.ExpiresAfter),
		time.Unix(0, req.ExpiresBefore),
		req.IssuerNameID,
		core.OCSPStatusRevoked,
	}

	selector, err := db.NewMappedSelector[crlEntryModel](ssa.dbReadOnlyMap)
	if err != nil {
		return fmt.Errorf("initializing db map: %w", err)
	}

	rows, err := selector.Query(stream.Context(), clauses, params...)
	if err != nil {
		return fmt.Errorf("reading db: %w", err)
	}

	defer func() {
		err := rows.Close()
		if err != nil {
			ssa.log.AuditErrf("closing row reader: %w", err)
		}
	}()

	for rows.Next() {
		row, err := rows.Get()
		if err != nil {
			return fmt.Errorf("reading row: %w", err)
		}

		// Double-check that the cert wasn't revoked between the time at which we're
		// constructing this snapshot CRL and right now. If the cert was revoked
		// at-or-after the "atTime", we'll just include it in the next generation
		// of CRLs.
		if row.RevokedDate.After(atTime) || row.RevokedDate.Equal(atTime) {
			continue
		}

		err = stream.Send(&corepb.CRLEntry{
			Serial:    row.Serial,
			Reason:    int32(row.RevokedReason),
			RevokedAt: row.RevokedDate.UnixNano(),
		})
		if err != nil {
			return fmt.Errorf("sending crl entry: %w", err)
		}
	}

	err = rows.Err()
	if err != nil {
		return fmt.Errorf("iterating over row reader: %w", err)
	}

	return nil
}
