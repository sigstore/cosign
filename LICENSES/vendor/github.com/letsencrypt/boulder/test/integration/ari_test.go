//go:build integration

package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/test"
	ocsp_helper "github.com/letsencrypt/boulder/test/ocsp/helper"
	"golang.org/x/crypto/ocsp"
)

func TestARI(t *testing.T) {
	t.Parallel()
	// This test is gated on the ServeRenewalInfo feature flag.
	if !strings.Contains(os.Getenv("BOULDER_CONFIG_DIR"), "test/config-next") {
		return
	}

	// Create an account.
	os.Setenv("DIRECTORY", "http://boulder:4001/directory")
	client, err := makeClient("mailto:example@letsencrypt.org")
	test.AssertNotError(t, err, "creating acme client")

	// Create a private key.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "creating random cert key")

	// Issue a cert.
	name := random_domain()
	ir, err := authAndIssue(client, key, []string{name})
	test.AssertNotError(t, err, "failed to issue test cert")
	cert := ir.certs[0]

	// Leverage OCSP to get components of ARI request path.
	issuer, err := ocsp_helper.GetIssuer(cert)
	test.AssertNotError(t, err, "failed to get issuer cert")
	ocspReqBytes, err := ocsp.CreateRequest(cert, issuer, nil)
	test.AssertNotError(t, err, "failed to build ocsp request")
	ocspReq, err := ocsp.ParseRequest(ocspReqBytes)
	test.AssertNotError(t, err, "failed to parse ocsp request")

	// Make ARI request.
	url := fmt.Sprintf(
		"http://boulder:4001/get/draft-aaron-ari/renewalInfo/%s/%s/%s",
		hex.EncodeToString(ocspReq.IssuerKeyHash),
		hex.EncodeToString(ocspReq.IssuerNameHash),
		core.SerialToString(cert.SerialNumber),
	)
	resp, err := http.Get(url)
	test.AssertNotError(t, err, "ARI request should have succeeded")
	test.AssertEquals(t, resp.StatusCode, http.StatusOK)

	// Try to make a new cert for a new domain, but have it fail so only
	// a precert gets created.
	name = random_domain()
	err = ctAddRejectHost(name)
	test.AssertNotError(t, err, "failed to add ct-test-srv reject host")
	_, err = authAndIssue(client, key, []string{name})
	test.AssertError(t, err, "expected error from authAndIssue, was nil")
	cert, err = ctFindRejection([]string{name})
	test.AssertNotError(t, err, "failed to find rejected precert")

	// Get ARI path components.
	issuer, err = ocsp_helper.GetIssuer(cert)
	test.AssertNotError(t, err, "failed to get issuer cert")
	ocspReqBytes, err = ocsp.CreateRequest(cert, issuer, nil)
	test.AssertNotError(t, err, "failed to build ocsp request")
	ocspReq, err = ocsp.ParseRequest(ocspReqBytes)
	test.AssertNotError(t, err, "failed to parse ocsp request")

	// Make ARI request.
	url = fmt.Sprintf(
		"http://boulder:4001/get/draft-aaron-ari/renewalInfo/%s/%s/%s",
		hex.EncodeToString(ocspReq.IssuerKeyHash),
		hex.EncodeToString(ocspReq.IssuerNameHash),
		core.SerialToString(cert.SerialNumber),
	)
	resp, err = http.Get(url)
	test.AssertNotError(t, err, "ARI request should have succeeded")
	test.AssertEquals(t, resp.StatusCode, http.StatusNotFound)
}
