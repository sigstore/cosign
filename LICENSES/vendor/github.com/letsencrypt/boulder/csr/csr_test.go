package csr

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/letsencrypt/boulder/core"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/goodkey"
	"github.com/letsencrypt/boulder/identifier"
	"github.com/letsencrypt/boulder/test"
)

var testingPolicy = &goodkey.KeyPolicy{
	AllowRSA:           true,
	AllowECDSANISTP256: true,
	AllowECDSANISTP384: true,
}

type mockPA struct{}

func (pa *mockPA) ChallengesFor(identifier identifier.ACMEIdentifier) (challenges []core.Challenge, err error) {
	return
}

func (pa *mockPA) WillingToIssue(id identifier.ACMEIdentifier) error {
	return nil
}

func (pa *mockPA) WillingToIssueWildcards(idents []identifier.ACMEIdentifier) error {
	for _, ident := range idents {
		if ident.Value == "bad-name.com" || ident.Value == "other-bad-name.com" {
			return errors.New("policy forbids issuing for identifier")
		}
	}
	return nil
}

func (pa *mockPA) ChallengeTypeEnabled(t core.AcmeChallenge) bool {
	return true
}

func TestVerifyCSR(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	test.AssertNotError(t, err, "error generating test key")
	signedReqBytes, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{PublicKey: private.PublicKey, SignatureAlgorithm: x509.SHA256WithRSA}, private)
	test.AssertNotError(t, err, "error generating test CSR")
	signedReq, err := x509.ParseCertificateRequest(signedReqBytes)
	test.AssertNotError(t, err, "error parsing test CSR")
	brokenSignedReq := new(x509.CertificateRequest)
	*brokenSignedReq = *signedReq
	brokenSignedReq.Signature = []byte{1, 1, 1, 1}
	signedReqWithHosts := new(x509.CertificateRequest)
	*signedReqWithHosts = *signedReq
	signedReqWithHosts.DNSNames = []string{"a.com", "b.com"}
	signedReqWithLongCN := new(x509.CertificateRequest)
	*signedReqWithLongCN = *signedReq
	signedReqWithLongCN.Subject.CommonName = strings.Repeat("a", maxCNLength+1)
	signedReqWithBadNames := new(x509.CertificateRequest)
	*signedReqWithBadNames = *signedReq
	signedReqWithBadNames.DNSNames = []string{"bad-name.com", "other-bad-name.com"}
	signedReqWithEmailAddress := new(x509.CertificateRequest)
	*signedReqWithEmailAddress = *signedReq
	signedReqWithEmailAddress.EmailAddresses = []string{"foo@bar.com"}
	signedReqWithIPAddress := new(x509.CertificateRequest)
	*signedReqWithIPAddress = *signedReq
	signedReqWithIPAddress.IPAddresses = []net.IP{net.IPv4(1, 2, 3, 4)}
	signedReqWithAllLongSANs := new(x509.CertificateRequest)
	*signedReqWithAllLongSANs = *signedReq
	signedReqWithAllLongSANs.DNSNames = []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com"}

	cases := []struct {
		csr           *x509.CertificateRequest
		maxNames      int
		keyPolicy     *goodkey.KeyPolicy
		pa            core.PolicyAuthority
		expectedError error
	}{
		{
			&x509.CertificateRequest{},
			100,
			testingPolicy,
			&mockPA{},
			invalidPubKey,
		},
		{
			&x509.CertificateRequest{PublicKey: &private.PublicKey},
			100,
			testingPolicy,
			&mockPA{},
			unsupportedSigAlg,
		},
		{
			brokenSignedReq,
			100,
			testingPolicy,
			&mockPA{},
			invalidSig,
		},
		{
			signedReq,
			100,
			testingPolicy,
			&mockPA{},
			invalidNoDNS,
		},
		{
			signedReqWithLongCN,
			100,
			testingPolicy,
			&mockPA{},
			berrors.BadCSRError("CN was longer than %d bytes", maxCNLength),
		},
		{
			signedReqWithHosts,
			1,
			testingPolicy,
			&mockPA{},
			berrors.BadCSRError("CSR contains more than 1 DNS names"),
		},
		{
			signedReqWithBadNames,
			100,
			testingPolicy,
			&mockPA{},
			errors.New("policy forbids issuing for identifier"),
		},
		{
			signedReqWithEmailAddress,
			100,
			testingPolicy,
			&mockPA{},
			invalidEmailPresent,
		},
		{
			signedReqWithIPAddress,
			100,
			testingPolicy,
			&mockPA{},
			invalidIPPresent,
		},
		{
			signedReqWithAllLongSANs,
			100,
			testingPolicy,
			&mockPA{},
			invalidAllSANTooLong,
		},
	}

	for _, c := range cases {
		err := VerifyCSR(context.Background(), c.csr, c.maxNames, c.keyPolicy, c.pa)
		test.AssertDeepEquals(t, c.expectedError, err)
	}
}

func TestNormalizeCSR(t *testing.T) {
	tooLongString := strings.Repeat("a", maxCNLength+1)

	cases := []struct {
		name          string
		csr           *x509.CertificateRequest
		expectedCN    string
		expectedNames []string
	}{
		{
			"no explicit CN",
			&x509.CertificateRequest{DNSNames: []string{"a.com"}},
			"a.com",
			[]string{"a.com"},
		},
		{
			"explicit uppercase CN",
			&x509.CertificateRequest{Subject: pkix.Name{CommonName: "A.com"}, DNSNames: []string{"a.com"}},
			"a.com",
			[]string{"a.com"},
		},
		{
			"no explicit CN, too long leading SANs",
			&x509.CertificateRequest{DNSNames: []string{
				tooLongString + ".a.com",
				tooLongString + ".b.com",
				"a.com",
				"b.com",
			}},
			"a.com",
			[]string{"a.com", tooLongString + ".a.com", tooLongString + ".b.com", "b.com"},
		},
		{
			"explicit CN, too long leading SANs",
			&x509.CertificateRequest{
				Subject: pkix.Name{CommonName: "A.com"},
				DNSNames: []string{
					tooLongString + ".a.com",
					tooLongString + ".b.com",
					"a.com",
					"b.com",
				}},
			"a.com",
			[]string{"a.com", tooLongString + ".a.com", tooLongString + ".b.com", "b.com"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			normalizeCSR(c.csr)
			test.AssertEquals(t, c.expectedCN, c.csr.Subject.CommonName)
			test.AssertDeepEquals(t, c.expectedNames, c.csr.DNSNames)
		})
	}
}

func TestSHA1Deprecation(t *testing.T) {
	features.Reset()

	private, err := rsa.GenerateKey(rand.Reader, 2048)
	test.AssertNotError(t, err, "error generating test key")

	makeAndVerifyCsr := func(alg x509.SignatureAlgorithm) error {
		csrBytes, err := x509.CreateCertificateRequest(rand.Reader,
			&x509.CertificateRequest{
				DNSNames:           []string{"example.com"},
				SignatureAlgorithm: alg,
				PublicKey:          &private.PublicKey,
			}, private)
		if err != nil {
			t.Fatal(err)
		}
		csr, err := x509.ParseCertificateRequest(csrBytes)
		if err != nil {
			t.Fatal(err)
		}
		return VerifyCSR(context.Background(), csr, 100, testingPolicy, &mockPA{})
	}

	err = makeAndVerifyCsr(x509.SHA256WithRSA)
	if err != nil {
		t.Fatalf("expected no error from VerifyCSR on a CSR signed with SHA256, got %s", err)
	}
	err = features.Set(map[string]bool{"SHA1CSRs": true})
	test.AssertNotError(t, err, "setting feature")
	err = makeAndVerifyCsr(x509.SHA1WithRSA)
	if err != nil {
		t.Fatalf("(SHA1CSR == true) expected no error from VerifyCSR on a CSR signed with SHA1, got %s (maybe set GODEBUG=x509sha1=1)", err)
	}

	err = features.Set(map[string]bool{"SHA1CSRs": false})
	test.AssertNotError(t, err, "setting feature")
	t.Logf("enabled %t\n", features.Enabled(features.SHA1CSRs))
	err = makeAndVerifyCsr(x509.SHA1WithRSA)
	if err == nil {
		t.Fatalf("(SHA1CSR == false) expected error from VerifyCSR on a CSR signed with SHA1, got none")
	}
}
