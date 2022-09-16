package crl

import (
	"encoding/pem"
	"os"
	"testing"

	"github.com/letsencrypt/boulder/crl/crl_x509"
	"github.com/letsencrypt/boulder/test"
	"github.com/zmap/zlint/v3/lint"
)

func loadPEMCRL(t *testing.T, filename string) *crl_x509.RevocationList {
	t.Helper()
	file, err := os.ReadFile(filename)
	test.AssertNotError(t, err, "reading CRL file")
	block, rest := pem.Decode(file)
	test.AssertEquals(t, block.Type, "X509 CRL")
	test.AssertEquals(t, len(rest), 0)
	crl, err := crl_x509.ParseRevocationList(block.Bytes)
	test.AssertNotError(t, err, "parsing CRL bytes")
	return crl
}

func TestHasIssuerName(t *testing.T) {
	crl := loadPEMCRL(t, "testdata/good.pem")
	res := hasIssuerName(crl)
	test.AssertEquals(t, res.Status, lint.Pass)

	crl = loadPEMCRL(t, "testdata/no_issuer_name.pem")
	res = hasIssuerName(crl)
	test.AssertEquals(t, res.Status, lint.Error)
	test.AssertContains(t, res.Details, "MUST have a non-empty issuer")
}

func TestHasNextUpdate(t *testing.T) {
	crl := loadPEMCRL(t, "testdata/good.pem")
	res := hasNextUpdate(crl)
	test.AssertEquals(t, res.Status, lint.Pass)

	crl = loadPEMCRL(t, "testdata/no_next_update.pem")
	res = hasNextUpdate(crl)
	test.AssertEquals(t, res.Status, lint.Error)
	test.AssertContains(t, res.Details, "MUST include the nextUpdate")
}

func TestNoEmptyRevokedCertificatesList(t *testing.T) {
	crl := loadPEMCRL(t, "testdata/good.pem")
	res := noEmptyRevokedCertificatesList(crl)
	test.AssertEquals(t, res.Status, lint.Pass)

	crl = loadPEMCRL(t, "testdata/none_revoked.pem")
	res = noEmptyRevokedCertificatesList(crl)
	test.AssertEquals(t, res.Status, lint.Pass)

	crl = loadPEMCRL(t, "testdata/empty_revoked.pem")
	res = noEmptyRevokedCertificatesList(crl)
	test.AssertEquals(t, res.Status, lint.Error)
	test.AssertContains(t, res.Details, "must not be present")
}

func TestHasAKI(t *testing.T) {
	crl := loadPEMCRL(t, "testdata/good.pem")
	res := hasAKI(crl)
	test.AssertEquals(t, res.Status, lint.Pass)

	crl = loadPEMCRL(t, "testdata/no_aki.pem")
	res = hasAKI(crl)
	test.AssertEquals(t, res.Status, lint.Error)
	test.AssertContains(t, res.Details, "MUST include the authority key identifier")

	crl = loadPEMCRL(t, "testdata/aki_name_and_serial.pem")
	res = hasAKI(crl)
	test.AssertEquals(t, res.Status, lint.Error)
	test.AssertContains(t, res.Details, "MUST use the key identifier method")
}

func TestHashNumber(t *testing.T) {
	crl := loadPEMCRL(t, "testdata/good.pem")
	res := hasNumber(crl)
	test.AssertEquals(t, res.Status, lint.Pass)

	crl = loadPEMCRL(t, "testdata/no_number.pem")
	res = hasNumber(crl)
	test.AssertEquals(t, res.Status, lint.Error)
	test.AssertContains(t, res.Details, "MUST include the CRL number")

	crl = loadPEMCRL(t, "testdata/critical_number.pem")
	res = hasNumber(crl)
	test.AssertEquals(t, res.Status, lint.Error)
	test.AssertContains(t, res.Details, "MUST NOT be marked critical")

	crl = loadPEMCRL(t, "testdata/long_number.pem")
	res = hasNumber(crl)
	test.AssertEquals(t, res.Status, lint.Error)
	test.AssertContains(t, res.Details, "MUST NOT be longer than 20 octets")
}

func TestIsNotDelta(t *testing.T) {
	crl := loadPEMCRL(t, "testdata/good.pem")
	res := isNotDelta(crl)
	test.AssertEquals(t, res.Status, lint.Pass)

	crl = loadPEMCRL(t, "testdata/delta.pem")
	res = isNotDelta(crl)
	test.AssertEquals(t, res.Status, lint.Notice)
	test.AssertContains(t, res.Details, "Delta")
}

func TestHasNoIDP(t *testing.T) {
	crl := loadPEMCRL(t, "testdata/good.pem")
	res := hasNoIDP(crl)
	test.AssertEquals(t, res.Status, lint.Pass)

	crl = loadPEMCRL(t, "testdata/idp.pem")
	res = hasNoIDP(crl)
	test.AssertEquals(t, res.Status, lint.Notice)
	test.AssertContains(t, res.Details, "Issuing Distribution Point")
}

func TestHasNoFreshest(t *testing.T) {
	crl := loadPEMCRL(t, "testdata/good.pem")
	res := hasNoFreshest(crl)
	test.AssertEquals(t, res.Status, lint.Pass)

	crl = loadPEMCRL(t, "testdata/freshest.pem")
	res = hasNoFreshest(crl)
	test.AssertEquals(t, res.Status, lint.Notice)
	test.AssertContains(t, res.Details, "Freshest")
}

func TestHasNoAIA(t *testing.T) {
	crl := loadPEMCRL(t, "testdata/good.pem")
	res := hasNoAIA(crl)
	test.AssertEquals(t, res.Status, lint.Pass)

	crl = loadPEMCRL(t, "testdata/aia.pem")
	res = hasNoAIA(crl)
	test.AssertEquals(t, res.Status, lint.Notice)
	test.AssertContains(t, res.Details, "Authority Information Access")
}

func TestHasNoCertIssuers(t *testing.T) {
	crl := loadPEMCRL(t, "testdata/good.pem")
	res := hasNoCertIssuers(crl)
	test.AssertEquals(t, res.Status, lint.Pass)

	crl = loadPEMCRL(t, "testdata/cert_issuer.pem")
	res = hasNoCertIssuers(crl)
	test.AssertEquals(t, res.Status, lint.Notice)
	test.AssertContains(t, res.Details, "Certificate Issuer")
}

func TestHasAcceptableValidity(t *testing.T) {
	crl := loadPEMCRL(t, "testdata/good.pem")
	res := hasAcceptableValidity(crl)
	test.AssertEquals(t, res.Status, lint.Pass)

	crl = loadPEMCRL(t, "testdata/negative_validity.pem")
	res = hasAcceptableValidity(crl)
	test.AssertEquals(t, res.Status, lint.Error)
	test.AssertContains(t, res.Details, "at or before")

	crl = loadPEMCRL(t, "testdata/long_validity.pem")
	res = hasAcceptableValidity(crl)
	test.AssertEquals(t, res.Status, lint.Error)
	test.AssertContains(t, res.Details, "greater than ten days")
}

func TestNoZeroReasonCodes(t *testing.T) {
	crl := loadPEMCRL(t, "testdata/good.pem")
	res := noZeroReasonCodes(crl)
	test.AssertEquals(t, res.Status, lint.Pass)

	crl = loadPEMCRL(t, "testdata/reason_0.pem")
	res = noZeroReasonCodes(crl)
	test.AssertEquals(t, res.Status, lint.Error)
	test.AssertContains(t, res.Details, "MUST NOT contain the unspecified")
}

func TestNoCriticalReasons(t *testing.T) {
	crl := loadPEMCRL(t, "testdata/good.pem")
	res := noCriticalReasons(crl)
	test.AssertEquals(t, res.Status, lint.Pass)

	crl = loadPEMCRL(t, "testdata/critical_reason.pem")
	res = noCriticalReasons(crl)
	test.AssertEquals(t, res.Status, lint.Error)
	test.AssertContains(t, res.Details, "reasonCodes MUST NOT be critical")
}

func TestNoCertificateHolds(t *testing.T) {
	crl := loadPEMCRL(t, "testdata/good.pem")
	res := noCertificateHolds(crl)
	test.AssertEquals(t, res.Status, lint.Pass)

	crl = loadPEMCRL(t, "testdata/reason_6.pem")
	res = noCertificateHolds(crl)
	test.AssertEquals(t, res.Status, lint.Error)
	test.AssertContains(t, res.Details, "MUST NOT use the certificateHold")
}

func TestHasMozReasonCodes(t *testing.T) {
	// good.pem contains a revocation entry with no reason code extension.
	crl := loadPEMCRL(t, "testdata/good.pem")
	res := hasMozReasonCodes(crl)
	test.AssertEquals(t, res.Status, lint.Pass)

	crl = loadPEMCRL(t, "testdata/reason_0.pem")
	res = hasMozReasonCodes(crl)
	test.AssertEquals(t, res.Status, lint.Error)
	test.AssertContains(t, res.Details, "MUST NOT include reasonCodes other than")

	crl = loadPEMCRL(t, "testdata/reason_1.pem")
	res = hasMozReasonCodes(crl)
	test.AssertEquals(t, res.Status, lint.Pass)

	crl = loadPEMCRL(t, "testdata/reason_2.pem")
	res = hasMozReasonCodes(crl)
	test.AssertEquals(t, res.Status, lint.Error)
	test.AssertContains(t, res.Details, "MUST NOT include reasonCodes other than")

	crl = loadPEMCRL(t, "testdata/reason_3.pem")
	res = hasMozReasonCodes(crl)
	test.AssertEquals(t, res.Status, lint.Pass)

	crl = loadPEMCRL(t, "testdata/reason_4.pem")
	res = hasMozReasonCodes(crl)
	test.AssertEquals(t, res.Status, lint.Pass)

	crl = loadPEMCRL(t, "testdata/reason_5.pem")
	res = hasMozReasonCodes(crl)
	test.AssertEquals(t, res.Status, lint.Pass)

	crl = loadPEMCRL(t, "testdata/reason_6.pem")
	res = hasMozReasonCodes(crl)
	test.AssertEquals(t, res.Status, lint.Error)
	test.AssertContains(t, res.Details, "MUST NOT include reasonCodes other than")

	crl = loadPEMCRL(t, "testdata/reason_8.pem")
	res = hasMozReasonCodes(crl)
	test.AssertEquals(t, res.Status, lint.Error)
	test.AssertContains(t, res.Details, "MUST NOT include reasonCodes other than")

	crl = loadPEMCRL(t, "testdata/reason_9.pem")
	res = hasMozReasonCodes(crl)
	test.AssertEquals(t, res.Status, lint.Pass)

	crl = loadPEMCRL(t, "testdata/reason_10.pem")
	res = hasMozReasonCodes(crl)
	test.AssertEquals(t, res.Status, lint.Error)
	test.AssertContains(t, res.Details, "MUST NOT include reasonCodes other than")
}
