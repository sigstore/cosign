package crl

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"time"

	"github.com/zmap/zlint/v3"
	"github.com/zmap/zlint/v3/lint"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/letsencrypt/boulder/crl/crl_x509"
)

type crlLint func(*crl_x509.RevocationList) *lint.LintResult

// registry is the collection of all known CRL lints. It is populated by this
// file's init(), and should not be touched by anything else on pain of races.
var registry map[string]crlLint

func init() {
	// NOTE TO DEVS: you MUST add your new lint function to this list or it
	// WILL NOT be run.
	registry = map[string]crlLint{
		"hasIssuerName":                  hasIssuerName,
		"hasNextUpdate":                  hasNextUpdate,
		"noEmptyRevokedCertificatesList": noEmptyRevokedCertificatesList,
		"hasAKI":                         hasAKI,
		"hasNumber":                      hasNumber,
		"isNotDelta":                     isNotDelta,
		"hasNoIDP":                       hasNoIDP,
		"hasNoFreshest":                  hasNoFreshest,
		"hasNoAIA":                       hasNoAIA,
		"noZeroReasonCodes":              noZeroReasonCodes,
		"hasNoCertIssuers":               hasNoCertIssuers,
		"hasAcceptableValidity":          hasAcceptableValidity,
		"noCriticalReasons":              noCriticalReasons,
		"noCertificateHolds":             noCertificateHolds,
		"hasMozReasonCodes":              hasMozReasonCodes,
	}
}

// getExtWithOID is a helper for several lints in this file. It returns the
// extension with the given OID if it exists, or nil otherwise.
func getExtWithOID(exts []pkix.Extension, oid asn1.ObjectIdentifier) *pkix.Extension {
	for _, ext := range exts {
		if ext.Id.Equal(oid) {
			return &ext
		}
	}
	return nil
}

// LintCRL examines the given lint CRL, runs it through all of our checks, and
// returns a list of all failures
func LintCRL(lintCRL *crl_x509.RevocationList) *zlint.ResultSet {
	rset := zlint.ResultSet{
		Version:   0,
		Timestamp: time.Now().UnixNano(),
		Results:   make(map[string]*lint.LintResult),
	}

	type namedResult struct {
		Name   string
		Result *lint.LintResult
	}
	resChan := make(chan namedResult, len(registry))

	for name, callable := range registry {
		go func(name string, callable crlLint) {
			resChan <- namedResult{name, callable(lintCRL)}
		}(name, callable)
	}

	for i := 0; i < len(registry); i++ {
		res := <-resChan
		switch res.Result.Status {
		case lint.Notice:
			rset.NoticesPresent = true
		case lint.Warn:
			rset.WarningsPresent = true
		case lint.Error:
			rset.ErrorsPresent = true
		case lint.Fatal:
			rset.FatalsPresent = true
		}
		rset.Results[res.Name] = res.Result
	}

	return &rset
}

// hasIssuerName checks RFC 5280, Section 5.1.2.3:
// The issuer field MUST contain a non-empty X.500 distinguished name (DN).
// This lint does not enforce that the issuer field complies with the rest of
// the encoding rules of a certificate issuer name, because it (perhaps wrongly)
// assumes that those were checked when the issuer was itself issued, and on all
// certificates issued by this CRL issuer. Also because there are just a lot of
// things to check there, and zlint doesn't expose a public helper for it.
func hasIssuerName(crl *crl_x509.RevocationList) *lint.LintResult {
	if len(crl.Issuer.Names) == 0 {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "CRLs MUST have a non-empty issuer field",
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}

// TODO(#6222): Write a lint which checks RFC 5280, Section 5.1.2.4 and 5.1.2.5:
// CRL issuers conforming to this profile MUST encode thisUpdate and nextUpdate
// as UTCTime for dates through the year 2049. UTCTime and GeneralizedTime
// values MUST be expressed in Greenwich Mean Time (Zulu) and MUST include
// seconds, even where the number of seconds is zero.

// hasNextUpdate checks RFC 5280, Section 5.1.2.5:
// Conforming CRL issuers MUST include the nextUpdate field in all CRLs.
func hasNextUpdate(crl *crl_x509.RevocationList) *lint.LintResult {
	if crl.NextUpdate.IsZero() {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "Conforming CRL issuers MUST include the nextUpdate field in all CRLs",
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}

// noEmptyRevokedCertificatesList checks RFC 5280, Section 5.1.2.6:
// When there are no revoked certificates, the revoked certificates list MUST be
// absent.
func noEmptyRevokedCertificatesList(crl *crl_x509.RevocationList) *lint.LintResult {
	if crl.RevokedCertificates != nil && len(crl.RevokedCertificates) == 0 {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "If the revokedCertificates list is empty, it must not be present",
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}

// hasAKI checks RFC 5280, Section 5.2.1:
// Conforming CRL issuers MUST use the key identifier method, and MUST include
// this extension in all CRLs issued.
func hasAKI(crl *crl_x509.RevocationList) *lint.LintResult {
	if len(crl.AuthorityKeyId) == 0 {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "CRLs MUST include the authority key identifier extension",
		}
	}
	aki := cryptobyte.String(crl.AuthorityKeyId)
	var akiBody cryptobyte.String
	if !aki.ReadASN1(&akiBody, cryptobyte_asn1.SEQUENCE) {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "CRL has a malformed authority key identifier extension",
		}
	}
	if !akiBody.PeekASN1Tag(cryptobyte_asn1.Tag(0).ContextSpecific()) {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "CRLs MUST use the key identifier method in the authority key identifier extension",
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}

// hasNumber checks RFC 5280, Section 5.2.3:
// CRL issuers conforming to this profile MUST include this extension in all
// CRLs and MUST mark this extension as non-critical. Conforming CRL issuers
// MUST NOT use CRLNumber values longer than 20 octets.
func hasNumber(crl *crl_x509.RevocationList) *lint.LintResult {
	if crl.Number == nil {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "CRLs MUST include the CRL number extension",
		}
	}

	crlNumberOID := asn1.ObjectIdentifier{2, 5, 29, 20} // id-ce-cRLNumber
	ext := getExtWithOID(crl.Extensions, crlNumberOID)
	if ext != nil && ext.Critical {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "CRL Number MUST NOT be marked critical",
		}
	}

	numBytes := crl.Number.Bytes()
	if len(numBytes) > 20 || (len(numBytes) == 20 && numBytes[0]&0x80 != 0) {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "CRL Number MUST NOT be longer than 20 octets",
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}

// isNotDelta checks that the CRL is not a Delta CRL. (RFC 5280, Section 5.2.4).
// There's no requirement against this, but Delta CRLs come with extra
// requirements we don't want to deal with.
func isNotDelta(crl *crl_x509.RevocationList) *lint.LintResult {
	deltaCRLIndicatorOID := asn1.ObjectIdentifier{2, 5, 29, 27} // id-ce-deltaCRLIndicator
	if getExtWithOID(crl.Extensions, deltaCRLIndicatorOID) != nil {
		return &lint.LintResult{
			Status:  lint.Notice,
			Details: "CRL is a Delta CRL",
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}

// hasNoIDP checks that the CRL does not have an Issuing Distribution Point
// extension (RFC 5280, Section 5.2.5). There's no requirement against this, but
// IDPs come with extra requirements we don't want to deal with.
func hasNoIDP(crl *crl_x509.RevocationList) *lint.LintResult {
	idpOID := asn1.ObjectIdentifier{2, 5, 29, 28} // id-ce-issuingDistributionPoint
	if getExtWithOID(crl.Extensions, idpOID) != nil {
		return &lint.LintResult{
			Status:  lint.Notice,
			Details: "CRL has an Issuing Distribution Point url",
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}

// hasNoFreshest checks that the CRL is does not have a Freshest CRL extension
// (RFC 5280, Section 5.2.6). There's no requirement against this, but Freshest
// CRL extensions (and the Delta CRLs they imply) come with extra requirements
// we don't want to deal with.
func hasNoFreshest(crl *crl_x509.RevocationList) *lint.LintResult {
	freshestOID := asn1.ObjectIdentifier{2, 5, 29, 46} // id-ce-freshestCRL
	if getExtWithOID(crl.Extensions, freshestOID) != nil {
		return &lint.LintResult{
			Status:  lint.Notice,
			Details: "CRL has a Freshest CRL url",
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}

// hasNoAIA checks that the CRL is does not have an Authority Information Access
// extension (RFC 5280, Section 5.2.7). There's no requirement against this, but
// AIAs come with extra requirements we don't want to deal with.
func hasNoAIA(crl *crl_x509.RevocationList) *lint.LintResult {
	aiaOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1} // id-pe-authorityInfoAccess
	if getExtWithOID(crl.Extensions, aiaOID) != nil {
		return &lint.LintResult{
			Status:  lint.Notice,
			Details: "CRL has an Authority Information Access url",
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}

// hasNoCertIssuers checks that the CRL does not have any entries with the
// Certificate Issuer extension (RFC 5280, Section 5.3.3). There is no
// requirement against this, but the presence of this extension would mean that
// the CRL includes certificates issued by an issuer other than the one signing
// the CRL itself, which we don't want to do.
func hasNoCertIssuers(crl *crl_x509.RevocationList) *lint.LintResult {
	certIssuerOID := asn1.ObjectIdentifier{2, 5, 29, 29} // id-ce-certificateIssuer
	for _, entry := range crl.RevokedCertificates {
		if getExtWithOID(entry.Extensions, certIssuerOID) != nil {
			return &lint.LintResult{
				Status:  lint.Notice,
				Details: "CRL has an entry with a Certificate Issuer extension",
			}
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}

// hasAcceptableValidity checks Baseline Requirements, Section 4.9.7:
// The value of the nextUpdate field MUST NOT be more than ten days beyond the
// value of the thisUpdate field.
func hasAcceptableValidity(crl *crl_x509.RevocationList) *lint.LintResult {
	validity := crl.NextUpdate.Sub(crl.ThisUpdate)
	if validity <= 0 {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "CRL has NextUpdate at or before ThisUpdate",
		}
	} else if validity > 10*24*time.Hour {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: "CRL has validity period greater than ten days",
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}

// noZeroReasonCodes checks Baseline Requirements, Section 7.2.2.1:
// The CRLReason indicated MUST NOT be unspecified (0). If the reason for
// revocation is unspecified, CAs MUST omit reasonCode entry extension, if
// allowed by the previous requirements.
// By extension, it therefore also checks RFC 5280, Section 5.3.1:
// The reason code CRL entry extension SHOULD be absent instead of using the
// unspecified (0) reasonCode value.
func noZeroReasonCodes(crl *crl_x509.RevocationList) *lint.LintResult {
	for _, entry := range crl.RevokedCertificates {
		if entry.ReasonCode != nil && *entry.ReasonCode == 0 {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: "CRL entries MUST NOT contain the unspecified (0) reason code",
			}
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}

// noCrticialReasons checks Baseline Requirements, Section 7.2.2.1:
// If present, [the reasonCode] extension MUST NOT be marked critical.
func noCriticalReasons(crl *crl_x509.RevocationList) *lint.LintResult {
	reasonCodeOID := asn1.ObjectIdentifier{2, 5, 29, 21} // id-ce-reasonCode
	for _, rc := range crl.RevokedCertificates {
		for _, ext := range rc.Extensions {
			if ext.Id.Equal(reasonCodeOID) && ext.Critical {
				return &lint.LintResult{
					Status:  lint.Error,
					Details: "CRL entry reasonCodes MUST NOT be critical",
				}
			}
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}

// noCertificateHolds checks Baseline Requirements, Section 7.2.2.1:
// The CRLReason MUST NOT be certificateHold (6).
func noCertificateHolds(crl *crl_x509.RevocationList) *lint.LintResult {
	for _, entry := range crl.RevokedCertificates {
		if entry.ReasonCode != nil && *entry.ReasonCode == 6 {
			return &lint.LintResult{
				Status:  lint.Error,
				Details: "CRL entries MUST NOT use the certificateHold (6) reason code",
			}
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}

// hasMozReasonCodes checks MRSP v2.8 Section 6.1.1:
// When the CRLReason code is not one of the following, then the reasonCode extension MUST NOT be provided:
// - keyCompromise (RFC 5280 CRLReason #1);
// - privilegeWithdrawn (RFC 5280 CRLReason #9);
// - cessationOfOperation (RFC 5280 CRLReason #5);
// - affiliationChanged (RFC 5280 CRLReason #3); or
// - superseded (RFC 5280 CRLReason #4).
func hasMozReasonCodes(crl *crl_x509.RevocationList) *lint.LintResult {
	for _, rc := range crl.RevokedCertificates {
		if rc.ReasonCode == nil {
			continue
		}
		switch *rc.ReasonCode {
		case 1: // keyCompromise
		case 3: // affiliationChanged
		case 4: // superseded
		case 5: // cessationOfOperation
		case 9: // privilegeWithdrawn
			continue
		default:
			return &lint.LintResult{
				Status:  lint.Error,
				Details: "CRLs MUST NOT include reasonCodes other than 1, 3, 4, 5, and 9",
			}
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
