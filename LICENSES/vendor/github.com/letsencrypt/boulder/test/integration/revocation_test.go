//go:build integration

package integration

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/eggsampler/acme/v3"
	"github.com/letsencrypt/boulder/test"
	ocsp_helper "github.com/letsencrypt/boulder/test/ocsp/helper"
	"golang.org/x/crypto/ocsp"
)

// isPrecert returns true if the provided cert has an extension with the OID
// equal to OIDExtensionCTPoison.
func isPrecert(cert *x509.Certificate) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDExtensionCTPoison) {
			return true
		}
	}
	return false
}

// TestRevocation tests that a certificate can be revoked using all of the
// RFC 8555 revocation authentication mechanisms. It does so for both certs and
// precerts (with no corresponding final cert), and for both the Unspecified and
// keyCompromise revocation reasons.
func TestRevocation(t *testing.T) {
	t.Parallel()

	// This test is gated on lacking the MozRevocationReasons feature flag.
	if strings.Contains(os.Getenv("BOULDER_CONFIG_DIR"), "test/config-next") {
		return
	}

	// Create a base account to use for revocation tests.
	os.Setenv("DIRECTORY", "http://boulder:4001/directory")

	type authMethod string
	var (
		byAccount authMethod = "byAccount"
		byAuth    authMethod = "byAuth"
		byKey     authMethod = "byKey"
	)

	type certKind string
	var (
		finalcert certKind = "cert"
		precert   certKind = "precert"
	)

	type testCase struct {
		method      authMethod
		reason      int
		kind        certKind
		expectError bool
	}

	var testCases []testCase
	for _, kind := range []certKind{precert, finalcert} {
		for _, reason := range []int{ocsp.Unspecified, ocsp.KeyCompromise} {
			for _, method := range []authMethod{byAccount, byAuth, byKey} {
				testCases = append(testCases, testCase{
					method: method,
					reason: reason,
					kind:   kind,
					// We expect an error only for KeyCompromise requests that use auth
					// methods other than using the certificate key itself.
					expectError: (reason == ocsp.KeyCompromise) && (method != byKey),
				})
			}
		}
	}

	for _, tc := range testCases {
		name := fmt.Sprintf("%s_%d_%s", tc.kind, tc.reason, tc.method)
		t.Run(name, func(t *testing.T) {
			issueClient, err := makeClient()
			test.AssertNotError(t, err, "creating acme client")

			certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			test.AssertNotError(t, err, "creating random cert key")

			domain := random_domain()

			// Try to issue a certificate for the name.
			var cert *x509.Certificate
			switch tc.kind {
			case finalcert:
				res, err := authAndIssue(issueClient, certKey, []string{domain})
				test.AssertNotError(t, err, "authAndIssue failed")
				cert = res.certs[0]

			case precert:
				// Make sure the ct-test-srv will reject generating SCTs for the domain,
				// so we only get a precert and no final cert.
				err := ctAddRejectHost(domain)
				test.AssertNotError(t, err, "adding ct-test-srv reject host")

				_, err = authAndIssue(issueClient, certKey, []string{domain})
				test.AssertError(t, err, "expected error from authAndIssue, was nil")
				if !strings.Contains(err.Error(), "urn:ietf:params:acme:error:serverInternal") ||
					!strings.Contains(err.Error(), "SCT embedding") {
					t.Fatal(err)
				}

				// Instead recover the precertificate from CT.
				cert, err = ctFindRejection([]string{domain})
				if err != nil || cert == nil {
					t.Fatalf("couldn't find rejected precert for %q", domain)
				}
				// And make sure the cert we found is in fact a precert.
				if !isPrecert(cert) {
					t.Fatal("precert was missing poison extension")
				}

			default:
				t.Fatalf("unrecognized cert kind %q", tc.kind)
			}

			// Initially, the cert should have a Good OCSP response.
			ocspConfig := ocsp_helper.DefaultConfig.WithExpectStatus(ocsp.Good)
			_, err = ocsp_helper.ReqDER(cert.Raw, ocspConfig)
			test.AssertNotError(t, err, "requesting OCSP for precert")

			// Set up the account and key that we'll use to try to revoke the cert.
			var revokeClient *client
			var revokeKey crypto.Signer
			switch tc.method {
			case byAccount:
				// When revoking by account, use the same client and key as were used
				// for the original issuance.
				revokeClient = issueClient
				revokeKey = revokeClient.PrivateKey

			case byAuth:
				// When revoking by auth, create a brand new client, authorize it for
				// the same domain, and use that account and key for revocation. Ignore
				// errors from authAndIssue because all we need is the auth, not the
				// issuance.
				revokeClient, err = makeClient()
				test.AssertNotError(t, err, "creating second acme client")
				_, _ = authAndIssue(revokeClient, certKey, []string{domain})
				revokeKey = revokeClient.PrivateKey

			case byKey:
				// When revoking by key, create a branch new client and use it and
				// the cert's key for revocation.
				revokeClient, err = makeClient()
				test.AssertNotError(t, err, "creating second acme client")
				revokeKey = certKey

			default:
				t.Fatalf("unrecognized revocation method %q", tc.method)
			}

			// Revoke the cert using the specified key and client.
			err = revokeClient.RevokeCertificate(
				revokeClient.Account,
				cert,
				revokeKey,
				tc.reason,
			)

			switch tc.expectError {
			case false:
				test.AssertNotError(t, err, "revocation should have succeeded")

				// Check the OCSP response for the certificate again. It should now be
				// revoked.
				ocspConfig = ocsp_helper.DefaultConfig.WithExpectStatus(ocsp.Revoked)
				_, err = ocsp_helper.ReqDER(cert.Raw, ocspConfig)
				test.AssertNotError(t, err, "requesting OCSP for revoked cert")

			case true:
				test.AssertError(t, err, "revocation should have failed")

				// Check the OCSP response for the certificate again. It should still
				// be good.
				ocspConfig = ocsp_helper.DefaultConfig.WithExpectStatus(ocsp.Good)
				_, err = ocsp_helper.ReqDER(cert.Raw, ocspConfig)
				test.AssertNotError(t, err, "requesting OCSP for nonrevoked cert")
			}
		})
	}
}

// TestMozRevocation tests that a certificate can be revoked using all of the
// RFC 8555 revocation authentication mechanisms. It does so for both certs and
// precerts (with no corresponding final cert), and for both the Unspecified and
// keyCompromise revocation reasons.
func TestMozRevocation(t *testing.T) {
	t.Parallel()

	// This test is gated on the MozRevocationReasons feature flag.
	if !strings.Contains(os.Getenv("BOULDER_CONFIG_DIR"), "test/config-next") {
		return
	}

	// Create a base account to use for revocation tests.
	os.Setenv("DIRECTORY", "http://boulder:4001/directory")

	type authMethod string
	var (
		byAccount authMethod = "byAccount"
		byAuth    authMethod = "byAuth"
		byKey     authMethod = "byKey"
	)

	type certKind string
	var (
		finalcert certKind = "cert"
		precert   certKind = "precert"
	)

	type testCase struct {
		method      authMethod
		reason      int
		kind        certKind
		expectError bool
	}

	var testCases []testCase
	for _, kind := range []certKind{precert, finalcert} {
		for _, reason := range []int{ocsp.Unspecified, ocsp.KeyCompromise} {
			for _, method := range []authMethod{byAccount, byAuth, byKey} {
				testCases = append(testCases, testCase{
					method: method,
					reason: reason,
					kind:   kind,
				})
			}
		}
	}

	for _, tc := range testCases {
		name := fmt.Sprintf("%s_%d_%s", tc.kind, tc.reason, tc.method)
		t.Run(name, func(t *testing.T) {
			issueClient, err := makeClient()
			test.AssertNotError(t, err, "creating acme client")

			certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			test.AssertNotError(t, err, "creating random cert key")

			domain := random_domain()

			// Try to issue a certificate for the name.
			var cert *x509.Certificate
			switch tc.kind {
			case finalcert:
				res, err := authAndIssue(issueClient, certKey, []string{domain})
				test.AssertNotError(t, err, "authAndIssue failed")
				cert = res.certs[0]

			case precert:
				// Make sure the ct-test-srv will reject generating SCTs for the domain,
				// so we only get a precert and no final cert.
				err := ctAddRejectHost(domain)
				test.AssertNotError(t, err, "adding ct-test-srv reject host")

				_, err = authAndIssue(issueClient, certKey, []string{domain})
				test.AssertError(t, err, "expected error from authAndIssue, was nil")
				if !strings.Contains(err.Error(), "urn:ietf:params:acme:error:serverInternal") ||
					!strings.Contains(err.Error(), "SCT embedding") {
					t.Fatal(err)
				}

				// Instead recover the precertificate from CT.
				cert, err = ctFindRejection([]string{domain})
				if err != nil || cert == nil {
					t.Fatalf("couldn't find rejected precert for %q", domain)
				}
				// And make sure the cert we found is in fact a precert.
				if !isPrecert(cert) {
					t.Fatal("precert was missing poison extension")
				}

			default:
				t.Fatalf("unrecognized cert kind %q", tc.kind)
			}

			// Initially, the cert should have a Good OCSP response.
			ocspConfig := ocsp_helper.DefaultConfig.WithExpectStatus(ocsp.Good)
			_, err = ocsp_helper.ReqDER(cert.Raw, ocspConfig)
			test.AssertNotError(t, err, "requesting OCSP for precert")

			// Set up the account and key that we'll use to revoke the cert.
			var revokeClient *client
			var revokeKey crypto.Signer
			switch tc.method {
			case byAccount:
				// When revoking by account, use the same client and key as were used
				// for the original issuance.
				revokeClient = issueClient
				revokeKey = revokeClient.PrivateKey

			case byAuth:
				// When revoking by auth, create a brand new client, authorize it for
				// the same domain, and use that account and key for revocation. Ignore
				// errors from authAndIssue because all we need is the auth, not the
				// issuance.
				revokeClient, err = makeClient()
				test.AssertNotError(t, err, "creating second acme client")
				_, _ = authAndIssue(revokeClient, certKey, []string{domain})
				revokeKey = revokeClient.PrivateKey

			case byKey:
				// When revoking by key, create a brand new client and use it with
				// the cert's key for revocation.
				revokeClient, err = makeClient()
				test.AssertNotError(t, err, "creating second acme client")
				revokeKey = certKey

			default:
				t.Fatalf("unrecognized revocation method %q", tc.method)
			}

			// Revoke the cert using the specified key and client.
			err = revokeClient.RevokeCertificate(
				revokeClient.Account,
				cert,
				revokeKey,
				tc.reason,
			)

			test.AssertNotError(t, err, "revocation should have succeeded")

			// Check the OCSP response for the certificate again. It should now be
			// revoked.
			ocspConfig = ocsp_helper.DefaultConfig.WithExpectStatus(ocsp.Revoked)
			_, err = ocsp_helper.ReqDER(cert.Raw, ocspConfig)
			test.AssertNotError(t, err, "requesting OCSP for revoked cert")
		})
	}
}

// TestDoubleRevocationOff verifies that a certificate cannot have its
// revocation reason updated (after the first time it has been revoked)
// for any reason.
func TestDoubleRevocationOff(t *testing.T) {
	t.Parallel()

	// This test is gated on lacking the AllowReRevocation feature flag.
	if strings.Contains(os.Getenv("BOULDER_CONFIG_DIR"), "test/config-next") {
		return
	}

	// Create a base account to use for revocation tests.
	os.Setenv("DIRECTORY", "http://boulder:4001/directory")

	client, err := makeClient()
	test.AssertNotError(t, err, "creating acme client")

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "creating random cert key")

	domain := random_domain()

	res, err := authAndIssue(client, certKey, []string{domain})
	test.AssertNotError(t, err, "authAndIssue failed")
	cert := res.certs[0]

	ocspConfig := ocsp_helper.DefaultConfig.WithExpectStatus(ocsp.Good)
	_, err = ocsp_helper.ReqDER(cert.Raw, ocspConfig)
	test.AssertNotError(t, err, "requesting OCSP for cert")

	// Have the original subscriber revoke the cert for any reason.
	err = client.RevokeCertificate(client.Account, cert, client.PrivateKey, 0)
	test.AssertNotError(t, err, "revocation should have succeeded")

	// Re-revoking for the same reason should fail.
	err = client.RevokeCertificate(client.Account, cert, client.PrivateKey, 0)
	test.AssertError(t, err, "re-revocation should have failed")

	// Re-revoking for a different reason should fail.
	err = client.RevokeCertificate(client.Account, cert, client.PrivateKey, 3)
	test.AssertError(t, err, "re-revocation should have failed")

	// Re-revoking for keyCompromise should fail.
	err = client.RevokeCertificate(client.Account, cert, client.PrivateKey, 1)
	test.AssertError(t, err, "re-revocation should have failed")

	// Re-revoking for keyCompromise using the cert key should fail.
	err = client.RevokeCertificate(client.Account, cert, certKey, 1)
	test.AssertError(t, err, "re-revocation should have failed")
}

// TestDoubleRevocationOn verifies that a certificate can have its revocation
// information updated only when both of the following are true:
// a) The certificate was not initially revoked for reason keyCompromise; and
// b) The second request is authenticated using the cert's keypair.
// In which case the revocation reason (but not revocation date) will be
// updated to be keyCompromise.
func TestDoubleRevocationOn(t *testing.T) {
	t.Parallel()

	// This test is gated on the AllowReRevocation feature flag.
	if !strings.Contains(os.Getenv("BOULDER_CONFIG_DIR"), "test/config-next") {
		return
	}

	// Create a base account to use for revocation tests.
	os.Setenv("DIRECTORY", "http://boulder:4001/directory")

	type authMethod string
	var (
		byAccount authMethod = "byAccount"
		byKey     authMethod = "byKey"
	)

	type testCase struct {
		method1     authMethod
		reason1     int
		method2     authMethod
		reason2     int
		expectError bool
	}

	testCases := []testCase{
		{method1: byAccount, reason1: 0, method2: byAccount, reason2: 0, expectError: true},
		{method1: byAccount, reason1: 1, method2: byAccount, reason2: 1, expectError: true},
		{method1: byAccount, reason1: 0, method2: byKey, reason2: 1, expectError: false},
		{method1: byAccount, reason1: 1, method2: byKey, reason2: 1, expectError: true},
		{method1: byKey, reason1: 1, method2: byKey, reason2: 1, expectError: true},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			issueClient, err := makeClient()
			test.AssertNotError(t, err, "creating acme client")

			certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			test.AssertNotError(t, err, "creating random cert key")

			// Try to issue a certificate for the name.
			domain := random_domain()
			res, err := authAndIssue(issueClient, certKey, []string{domain})
			test.AssertNotError(t, err, "authAndIssue failed")
			cert := res.certs[0]

			// Initially, the cert should have a Good OCSP response.
			ocspConfig := ocsp_helper.DefaultConfig.WithExpectStatus(ocsp.Good)
			_, err = ocsp_helper.ReqDER(cert.Raw, ocspConfig)
			test.AssertNotError(t, err, "requesting OCSP for precert")

			// Set up the account and key that we'll use to revoke the cert.
			var revokeClient *client
			var revokeKey crypto.Signer
			switch tc.method1 {
			case byAccount:
				// When revoking by account, use the same client and key as were used
				// for the original issuance.
				revokeClient = issueClient
				revokeKey = revokeClient.PrivateKey

			case byKey:
				// When revoking by key, create a brand new client and use it with
				// the cert's key for revocation.
				revokeClient, err = makeClient()
				test.AssertNotError(t, err, "creating second acme client")
				revokeKey = certKey

			default:
				t.Fatalf("unrecognized revocation method %q", tc.method1)
			}

			// Revoke the cert using the specified key and client.
			err = revokeClient.RevokeCertificate(
				revokeClient.Account,
				cert,
				revokeKey,
				tc.reason1,
			)
			test.AssertNotError(t, err, "initial revocation should have succeeded")

			// Check the OCSP response for the certificate again. It should now be
			// revoked.
			ocspConfig = ocsp_helper.DefaultConfig.WithExpectStatus(ocsp.Revoked).WithExpectReason(tc.reason1)
			_, err = ocsp_helper.ReqDER(cert.Raw, ocspConfig)
			test.AssertNotError(t, err, "requesting OCSP for revoked cert")

			// Set up the account and key that we'll use to *re*-revoke the cert.
			switch tc.method2 {
			case byAccount:
				// When revoking by account, use the same client and key as were used
				// for the original issuance.
				revokeClient = issueClient
				revokeKey = revokeClient.PrivateKey

			case byKey:
				// When revoking by key, create a brand new client and use it with
				// the cert's key for revocation.
				revokeClient, err = makeClient()
				test.AssertNotError(t, err, "creating second acme client")
				revokeKey = certKey

			default:
				t.Fatalf("unrecognized revocation method %q", tc.method2)
			}

			// Re-revoke the cert using the specified key and client.
			err = revokeClient.RevokeCertificate(
				revokeClient.Account,
				cert,
				revokeKey,
				tc.reason2,
			)

			switch tc.expectError {
			case true:
				test.AssertError(t, err, "second revocation should have failed")

				// Check the OCSP response for the certificate again. It should still be
				// revoked, with the same reason.
				ocspConfig = ocsp_helper.DefaultConfig.WithExpectStatus(ocsp.Revoked).WithExpectReason(tc.reason1)
				_, err = ocsp_helper.ReqDER(cert.Raw, ocspConfig)
				test.AssertNotError(t, err, "requesting OCSP for revoked cert")

			case false:
				test.AssertNotError(t, err, "second revocation should have succeeded")

				// Check the OCSP response for the certificate again. It should now be
				// revoked with reason keyCompromise.
				ocspConfig = ocsp_helper.DefaultConfig.WithExpectStatus(ocsp.Revoked).WithExpectStatus(tc.reason2)
				_, err = ocsp_helper.ReqDER(cert.Raw, ocspConfig)
				test.AssertNotError(t, err, "requesting OCSP for revoked cert")
			}
		})
	}
}

func TestRevokeWithKeyCompromise(t *testing.T) {
	t.Parallel()
	os.Setenv("DIRECTORY", "http://boulder:4001/directory")
	c, err := makeClient("mailto:example@letsencrypt.org")
	test.AssertNotError(t, err, "creating acme client")

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "failed to generate cert key")

	res, err := authAndIssue(c, certKey, []string{random_domain()})
	test.AssertNotError(t, err, "authAndIssue failed")

	cert := res.certs[0]

	err = c.RevokeCertificate(
		acme.Account{},
		cert,
		certKey,
		ocsp.KeyCompromise,
	)
	test.AssertNotError(t, err, "failed to revoke certificate")

	// attempt to create a new account using the blocklisted key
	_, err = c.NewAccount(certKey, false, true)
	test.AssertError(t, err, "NewAccount didn't fail with a blocklisted key")
	test.AssertEquals(t, err.Error(), `acme: error code 400 "urn:ietf:params:acme:error:badPublicKey": public key is forbidden`)

	// Check the OCSP response. It should be revoked with reason = 1 (keyCompromise)
	ocspConfig := ocsp_helper.DefaultConfig.WithExpectStatus(ocsp.Revoked)
	response, err := ocsp_helper.ReqDER(cert.Raw, ocspConfig)
	test.AssertNotError(t, err, "requesting OCSP for revoked cert")
	test.AssertEquals(t, response.RevocationReason, 1)
}

func TestBadKeyRevoker(t *testing.T) {
	t.Parallel()
	os.Setenv("DIRECTORY", "http://boulder:4001/directory")
	cA, err := makeClient("mailto:bad-key-revoker-revoker@letsencrypt.org", "mailto:bad-key-revoker-revoker-2@letsencrypt.org")
	test.AssertNotError(t, err, "creating acme client")
	cB, err := makeClient("mailto:bad-key-revoker-revoker-2@letsencrypt.org")
	test.AssertNotError(t, err, "creating acme client")
	cC, err := makeClient("mailto:bad-key-revoker-revokee@letsencrypt.org", "mailto:bad-key-revoker-revokee-2@letsencrypt.org")
	test.AssertNotError(t, err, "creating acme client")
	cD, err := makeClient("mailto:bad-key-revoker-revokee-2@letsencrypt.org", "mailto:bad-key-revoker-revokee@letsencrypt.org")
	test.AssertNotError(t, err, "creating acme client")
	cE, err := makeClient()
	test.AssertNotError(t, err, "creating acme client")

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "failed to generate cert key")

	badCert, err := authAndIssue(cA, certKey, []string{random_domain()})
	test.AssertNotError(t, err, "authAndIssue failed")

	certs := []*x509.Certificate{}
	for _, c := range []*client{cA, cB, cC, cD, cE} {
		for i := 0; i < 2; i++ {
			cert, err := authAndIssue(c, certKey, []string{random_domain()})
			test.AssertNotError(t, err, "authAndIssue failed")
			certs = append(certs, cert.certs[0])
		}
	}

	err = cA.RevokeCertificate(
		acme.Account{},
		badCert.certs[0],
		certKey,
		ocsp.KeyCompromise,
	)
	test.AssertNotError(t, err, "failed to revoke certificate")
	ocspConfig := ocsp_helper.DefaultConfig.WithExpectStatus(ocsp.Revoked)
	_, err = ocsp_helper.ReqDER(badCert.certs[0].Raw, ocspConfig)
	test.AssertNotError(t, err, "ReqDER failed")

	for _, cert := range certs {
		for i := 0; i < 5; i++ {
			_, err = ocsp_helper.ReqDER(cert.Raw, ocspConfig)
			if err == nil {
				break
			}
			if i == 5 {
				t.Fatal("timed out waiting for revoked OCSP status")
			}
			time.Sleep(time.Second)
		}
	}

	countResp, err := http.Get("http://boulder:9381/count?to=bad-key-revoker-revokee@letsencrypt.org")
	test.AssertNotError(t, err, "mail-test-srv GET /count failed")
	defer func() { _ = countResp.Body.Close() }()
	body, err := ioutil.ReadAll(countResp.Body)
	test.AssertNotError(t, err, "failed to read body")
	test.AssertEquals(t, string(body), "1\n")
	otherCountResp, err := http.Get("http://boulder:9381/count?to=bad-key-revoker-revokee-2@letsencrypt.org")
	test.AssertNotError(t, err, "mail-test-srv GET /count failed")
	defer func() { _ = otherCountResp.Body.Close() }()
	body, err = ioutil.ReadAll(otherCountResp.Body)
	test.AssertNotError(t, err, "failed to read body")
	test.AssertEquals(t, string(body), "1\n")

	zeroCountResp, err := http.Get("http://boulder:9381/count?to=bad-key-revoker-revoker@letsencrypt.org")
	test.AssertNotError(t, err, "mail-test-srv GET /count failed")
	defer func() { _ = zeroCountResp.Body.Close() }()
	body, err = ioutil.ReadAll(zeroCountResp.Body)
	test.AssertNotError(t, err, "failed to read body")
	test.AssertEquals(t, string(body), "1\n")
}
