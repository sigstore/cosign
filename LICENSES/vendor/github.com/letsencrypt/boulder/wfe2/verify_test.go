package wfe2

import (
	"context"
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/mocks"
	"github.com/letsencrypt/boulder/probs"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/web"
	"github.com/prometheus/client_golang/prometheus"

	"google.golang.org/grpc"
	"gopkg.in/square/go-jose.v2"
)

// sigAlgForKey uses `signatureAlgorithmForKey` but fails immediately using the
// testing object if the sig alg is unknown.
func sigAlgForKey(t *testing.T, key interface{}) jose.SignatureAlgorithm {
	var sigAlg jose.SignatureAlgorithm
	var err error
	// Gracefully handle the case where a non-pointer public key is given where
	// sigAlgorithmForKey always wants a pointer. It may be tempting to try and do
	// `sigAlgorithmForKey(&jose.JSONWebKey{Key: &key})` without a type switch but this produces
	// `*interface {}` and not the desired `*rsa.PublicKey` or `*ecdsa.PublicKey`.
	switch k := key.(type) {
	case rsa.PublicKey:
		sigAlg, err = sigAlgorithmForKey(&jose.JSONWebKey{Key: &k})
	case ecdsa.PublicKey:
		sigAlg, err = sigAlgorithmForKey(&jose.JSONWebKey{Key: &k})
	default:
		sigAlg, err = sigAlgorithmForKey(&jose.JSONWebKey{Key: k})
	}
	test.Assert(t, err == nil, fmt.Sprintf("Error getting signature algorithm for key %#v", key))
	return sigAlg
}

// keyAlgForKey returns a JWK key algorithm based on the provided private key.
// Only ECDSA and RSA private keys are supported.
func keyAlgForKey(t *testing.T, key interface{}) string {
	switch key.(type) {
	case *rsa.PrivateKey, rsa.PrivateKey:
		return "RSA"
	case *ecdsa.PrivateKey, ecdsa.PrivateKey:
		return "ECDSA"
	}
	t.Fatalf("Can't figure out keyAlgForKey: %#v", key)
	return ""
}

// pubKeyForKey returns the public key of an RSA/ECDSA private key provided as
// argument.
func pubKeyForKey(t *testing.T, privKey interface{}) interface{} {
	switch k := privKey.(type) {
	case *rsa.PrivateKey:
		return k.PublicKey
	case *ecdsa.PrivateKey:
		return k.PublicKey
	}
	t.Fatalf("Unable to get public key for private key %#v", privKey)
	return nil
}

// signRequestEmbed creates a JWS for a given request body with an embedded JWK
// corresponding to the private key provided. The URL and nonce extra headers
// are set based on the additional arguments. A computed JWS, the corresponding
// embedded JWK and the JWS in serialized string form are returned.
func signRequestEmbed(
	t *testing.T,
	privateKey interface{},
	url string,
	req string,
	nonceService jose.NonceSource) (*jose.JSONWebSignature, *jose.JSONWebKey, string) {
	// if no key is provided default to test1KeyPrivatePEM
	var publicKey interface{}
	if privateKey == nil {
		signer := loadKey(t, []byte(test1KeyPrivatePEM))
		privateKey = signer
		publicKey = signer.Public()
	} else {
		publicKey = pubKeyForKey(t, privateKey)
	}

	signerKey := jose.SigningKey{
		Key:       privateKey,
		Algorithm: sigAlgForKey(t, publicKey),
	}

	opts := &jose.SignerOptions{
		NonceSource: nonceService,
		EmbedJWK:    true,
	}
	if url != "" {
		opts.ExtraHeaders = map[jose.HeaderKey]interface{}{
			"url": url,
		}
	}

	signer, err := jose.NewSigner(signerKey, opts)
	test.AssertNotError(t, err, "Failed to make signer")

	jws, err := signer.Sign([]byte(req))
	test.AssertNotError(t, err, "Failed to sign req")

	body := jws.FullSerialize()
	parsedJWS, err := jose.ParseSigned(body)
	test.AssertNotError(t, err, "Failed to parse generated JWS")

	return parsedJWS, parsedJWS.Signatures[0].Header.JSONWebKey, body
}

// signRequestKeyID creates a JWS for a given request body with key ID specified
// based on the ID number provided. The URL and nonce extra headers
// are set based on the additional arguments. A computed JWS, the corresponding
// embedded JWK and the JWS in serialized string form are returned.
func signRequestKeyID(
	t *testing.T,
	keyID int64,
	privateKey interface{},
	url string,
	req string,
	nonceService jose.NonceSource) (*jose.JSONWebSignature, *jose.JSONWebKey, string) {
	// if no key is provided default to test1KeyPrivatePEM
	if privateKey == nil {
		privateKey = loadKey(t, []byte(test1KeyPrivatePEM))
	}

	jwk := &jose.JSONWebKey{
		Key:       privateKey,
		Algorithm: keyAlgForKey(t, privateKey),
		KeyID:     fmt.Sprintf("http://localhost/acme/acct/%d", keyID),
	}

	signerKey := jose.SigningKey{
		Key:       jwk,
		Algorithm: jose.RS256,
	}

	opts := &jose.SignerOptions{
		NonceSource: nonceService,
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": url,
		},
	}

	signer, err := jose.NewSigner(signerKey, opts)
	test.AssertNotError(t, err, "Failed to make signer")
	jws, err := signer.Sign([]byte(req))
	test.AssertNotError(t, err, "Failed to sign req")

	body := jws.FullSerialize()
	parsedJWS, err := jose.ParseSigned(body)
	test.AssertNotError(t, err, "Failed to parse generated JWS")

	return parsedJWS, jwk, body
}

func TestRejectsNone(t *testing.T) {
	noneJWSBody := `
		{
			"header": {
				"alg": "none",
				"jwk": {
					"kty": "RSA",
					"n": "vrjT",
					"e": "AQAB"
				}
			},
			"payload": "aGkK",
  		"signature": "ghTIjrhiRl2pQ09vAkUUBbF5KziJdhzOTB-okM9SPRzU8Hyj0W1H5JA1Zoc-A-LuJGNAtYYHWqMw1SeZbT0l9FHcbMPeWDaJNkHS9jz5_g_Oyol8vcrWur2GDtB2Jgw6APtZKrbuGATbrF7g41Wijk6Kk9GXDoCnlfOQOhHhsrFFcWlCPLG-03TtKD6EBBoVBhmlp8DRLs7YguWRZ6jWNaEX-1WiRntBmhLqoqQFtvZxCBw_PRuaRw_RZBd1x2_BNYqEdOmVNC43UHMSJg3y_3yrPo905ur09aUTscf-C_m4Sa4M0FuDKn3bQ_pFrtz-aCCq6rcTIyxYpDqNvHMT2Q"
		}
	`
	noneJWS, err := jose.ParseSigned(noneJWSBody)
	if err != nil {
		t.Fatal("Unable to parse noneJWS")
	}
	noneJWK := noneJWS.Signatures[0].Header.JSONWebKey

	err = checkAlgorithm(noneJWK, noneJWS)
	if err == nil {
		t.Fatalf("checkAlgorithm did not reject JWS with alg: 'none'")
	}
	if err.Error() != "JWS signature header contains unsupported algorithm \"none\", expected one of RS256, ES256, ES384 or ES512" {
		t.Fatalf("checkAlgorithm rejected JWS with alg: 'none', but for wrong reason: %#v", err)
	}
}

func TestRejectsHS256(t *testing.T) {
	hs256JWSBody := `
		{
			"header": {
				"alg": "HS256",
				"jwk": {
					"kty": "RSA",
					"n": "vrjT",
					"e": "AQAB"
				}
			},
			"payload": "aGkK",
  		"signature": "ghTIjrhiRl2pQ09vAkUUBbF5KziJdhzOTB-okM9SPRzU8Hyj0W1H5JA1Zoc-A-LuJGNAtYYHWqMw1SeZbT0l9FHcbMPeWDaJNkHS9jz5_g_Oyol8vcrWur2GDtB2Jgw6APtZKrbuGATbrF7g41Wijk6Kk9GXDoCnlfOQOhHhsrFFcWlCPLG-03TtKD6EBBoVBhmlp8DRLs7YguWRZ6jWNaEX-1WiRntBmhLqoqQFtvZxCBw_PRuaRw_RZBd1x2_BNYqEdOmVNC43UHMSJg3y_3yrPo905ur09aUTscf-C_m4Sa4M0FuDKn3bQ_pFrtz-aCCq6rcTIyxYpDqNvHMT2Q"
		}
	`

	hs256JWS, err := jose.ParseSigned(hs256JWSBody)
	if err != nil {
		t.Fatal("Unable to parse hs256JWSBody")
	}
	hs256JWK := hs256JWS.Signatures[0].Header.JSONWebKey

	err = checkAlgorithm(hs256JWK, hs256JWS)
	if err == nil {
		t.Fatalf("checkAlgorithm did not reject JWS with alg: 'HS256'")
	}
	expected := "JWS signature header contains unsupported algorithm \"HS256\", expected one of RS256, ES256, ES384 or ES512"
	if err.Error() != expected {
		t.Fatalf("checkAlgorithm rejected JWS with alg: 'none', but for wrong reason: got %q, wanted %q", err.Error(), expected)
	}
}

func TestCheckAlgorithm(t *testing.T) {
	testCases := []struct {
		key         jose.JSONWebKey
		jws         jose.JSONWebSignature
		expectedErr string
	}{
		{
			jose.JSONWebKey{},
			jose.JSONWebSignature{
				Signatures: []jose.Signature{
					{
						Header: jose.Header{
							Algorithm: "HS256",
						},
					},
				},
			},
			"JWS signature header contains unsupported algorithm \"HS256\", expected one of RS256, ES256, ES384 or ES512",
		},
		{
			jose.JSONWebKey{
				Key: &dsa.PublicKey{},
			},
			jose.JSONWebSignature{
				Signatures: []jose.Signature{
					{
						Header: jose.Header{
							Algorithm: "ES512",
						},
					},
				},
			},
			"JWK contains unsupported key type (expected RSA, or ECDSA P-256, P-384, or P-521",
		},
		{
			jose.JSONWebKey{
				Algorithm: "RS256",
				Key:       &rsa.PublicKey{},
			},
			jose.JSONWebSignature{
				Signatures: []jose.Signature{
					{
						Header: jose.Header{
							Algorithm: "ES512",
						},
					},
				},
			},
			"JWS signature header algorithm \"ES512\" does not match expected algorithm \"RS256\" for JWK",
		},
		{
			jose.JSONWebKey{
				Algorithm: "HS256",
				Key:       &rsa.PublicKey{},
			},
			jose.JSONWebSignature{
				Signatures: []jose.Signature{
					{
						Header: jose.Header{
							Algorithm: "RS256",
						},
					},
				},
			},
			"JWK key header algorithm \"HS256\" does not match expected algorithm \"RS256\" for JWK",
		},
	}
	for i, tc := range testCases {
		err := checkAlgorithm(&tc.key, &tc.jws)
		if tc.expectedErr != "" && err.Error() != tc.expectedErr {
			t.Errorf("TestCheckAlgorithm %d: Expected %q, got %q", i, tc.expectedErr, err)
		}
	}
}

func TestCheckAlgorithmSuccess(t *testing.T) {
	err := checkAlgorithm(&jose.JSONWebKey{
		Algorithm: "RS256",
		Key:       &rsa.PublicKey{},
	}, &jose.JSONWebSignature{
		Signatures: []jose.Signature{
			{
				Header: jose.Header{
					Algorithm: "RS256",
				},
			},
		},
	})
	if err != nil {
		t.Errorf("RS256 key: Expected nil error, got '%s'", err)
	}
	err = checkAlgorithm(&jose.JSONWebKey{
		Key: &rsa.PublicKey{},
	}, &jose.JSONWebSignature{
		Signatures: []jose.Signature{
			{
				Header: jose.Header{
					Algorithm: "RS256",
				},
			},
		},
	})
	if err != nil {
		t.Errorf("RS256 key: Expected nil error, got '%s'", err)
	}

	err = checkAlgorithm(&jose.JSONWebKey{
		Algorithm: "ES256",
		Key: &ecdsa.PublicKey{
			Curve: elliptic.P256(),
		},
	}, &jose.JSONWebSignature{
		Signatures: []jose.Signature{
			{
				Header: jose.Header{
					Algorithm: "ES256",
				},
			},
		},
	})
	if err != nil {
		t.Errorf("ES256 key: Expected nil error, got '%s'", err)
	}

	err = checkAlgorithm(&jose.JSONWebKey{
		Key: &ecdsa.PublicKey{
			Curve: elliptic.P256(),
		},
	}, &jose.JSONWebSignature{
		Signatures: []jose.Signature{
			{
				Header: jose.Header{
					Algorithm: "ES256",
				},
			},
		},
	})
	if err != nil {
		t.Errorf("ES256 key: Expected nil error, got '%s'", err)
	}
}

func TestValidPOSTRequest(t *testing.T) {
	wfe, _ := setupWFE(t)

	dummyContentLength := []string{"pretty long, idk, maybe a nibble or two?"}

	testCases := []struct {
		Name               string
		Headers            map[string][]string
		Body               *string
		HTTPStatus         int
		ProblemDetail      string
		ErrorStatType      string
		EnforceContentType bool
	}{
		// POST requests without a Content-Length should produce a problem
		{
			Name:          "POST without a Content-Length header",
			Headers:       nil,
			HTTPStatus:    http.StatusLengthRequired,
			ProblemDetail: "missing Content-Length header",
			ErrorStatType: "ContentLengthRequired",
		},
		// POST requests with a Replay-Nonce header should produce a problem
		{
			Name: "POST with a Replay-Nonce HTTP header",
			Headers: map[string][]string{
				"Content-Length": dummyContentLength,
				"Replay-Nonce":   {"ima-misplaced-nonce"},
				"Content-Type":   {expectedJWSContentType},
			},
			HTTPStatus:    http.StatusBadRequest,
			ProblemDetail: "HTTP requests should NOT contain Replay-Nonce header. Use JWS nonce field",
			ErrorStatType: "ReplayNonceOutsideJWS",
		},
		// POST requests without a body should produce a problem
		{
			Name: "POST with an empty POST body",
			Headers: map[string][]string{
				"Content-Length": dummyContentLength,
				"Content-Type":   {expectedJWSContentType},
			},
			HTTPStatus:    http.StatusBadRequest,
			ProblemDetail: "No body on POST",
			ErrorStatType: "NoPOSTBody",
		},
		{
			Name: "POST without a Content-Type header",
			Headers: map[string][]string{
				"Content-Length": dummyContentLength,
			},
			HTTPStatus: http.StatusUnsupportedMediaType,
			ProblemDetail: fmt.Sprintf(
				"No Content-Type header on POST. Content-Type must be %q",
				expectedJWSContentType),
			ErrorStatType:      "NoContentType",
			EnforceContentType: true,
		},
		{
			Name: "POST with an invalid Content-Type header",
			Headers: map[string][]string{
				"Content-Length": dummyContentLength,
				"Content-Type":   {"fresh.and.rare"},
			},
			HTTPStatus: http.StatusUnsupportedMediaType,
			ProblemDetail: fmt.Sprintf(
				"Invalid Content-Type header on POST. Content-Type must be %q",
				expectedJWSContentType),
			ErrorStatType:      "WrongContentType",
			EnforceContentType: true,
		},
	}

	for _, tc := range testCases {
		input := &http.Request{
			Method: "POST",
			URL:    mustParseURL("/"),
			Header: tc.Headers,
		}
		t.Run(tc.Name, func(t *testing.T) {
			prob := wfe.validPOSTRequest(input)
			test.Assert(t, prob != nil, "No error returned for invalid POST")
			test.AssertEquals(t, prob.Type, probs.MalformedProblem)
			test.AssertEquals(t, prob.HTTPStatus, tc.HTTPStatus)
			test.AssertEquals(t, prob.Detail, tc.ProblemDetail)
			test.AssertMetricWithLabelsEquals(
				t, wfe.stats.httpErrorCount, prometheus.Labels{"type": tc.ErrorStatType}, 1)
		})
	}
}

func TestEnforceJWSAuthType(t *testing.T) {
	wfe, _ := setupWFE(t)

	testKeyIDJWS, _, _ := signRequestKeyID(t, 1, nil, "", "", wfe.nonceService)
	testEmbeddedJWS, _, _ := signRequestEmbed(t, nil, "", "", wfe.nonceService)

	// A hand crafted JWS that has both a Key ID and an embedded JWK
	conflictJWSBody := `
{
  "header": {
    "alg": "RS256", 
    "jwk": {
      "e": "AQAB", 
      "kty": "RSA", 
      "n": "ppbqGaMFnnq9TeMUryR6WW4Lr5WMgp46KlBXZkNaGDNQoifWt6LheeR5j9MgYkIFU7Z8Jw5-bpJzuBeEVwb-yHGh4Umwo_qKtvAJd44iLjBmhBSxq-OSe6P5hX1LGCByEZlYCyoy98zOtio8VK_XyS5VoOXqchCzBXYf32ksVUTrtH1jSlamKHGz0Q0pRKIsA2fLqkE_MD3jP6wUDD6ExMw_tKYLx21lGcK41WSrRpDH-kcZo1QdgCy2ceNzaliBX1eHmKG0-H8tY4tPQudk-oHQmWTdvUIiHO6gSKMGDZNWv6bq74VTCsRfUEAkuWhqUhgRSGzlvlZ24wjHv5Qdlw"
    }
  }, 
  "protected": "eyJub25jZSI6ICJibTl1WTJVIiwgInVybCI6ICJodHRwOi8vbG9jYWxob3N0L3Rlc3QiLCAia2lkIjogInRlc3RrZXkifQ", 
  "payload": "Zm9v", 
  "signature": "ghTIjrhiRl2pQ09vAkUUBbF5KziJdhzOTB-okM9SPRzU8Hyj0W1H5JA1Zoc-A-LuJGNAtYYHWqMw1SeZbT0l9FHcbMPeWDaJNkHS9jz5_g_Oyol8vcrWur2GDtB2Jgw6APtZKrbuGATbrF7g41Wijk6Kk9GXDoCnlfOQOhHhsrFFcWlCPLG-03TtKD6EBBoVBhmlp8DRLs7YguWRZ6jWNaEX-1WiRntBmhLqoqQFtvZxCBw_PRuaRw_RZBd1x2_BNYqEdOmVNC43UHMSJg3y_3yrPo905ur09aUTscf-C_m4Sa4M0FuDKn3bQ_pFrtz-aCCq6rcTIyxYpDqNvHMT2Q"
}
`

	conflictJWS, err := jose.ParseSigned(conflictJWSBody)
	if err != nil {
		t.Fatal("Unable to parse conflict JWS")
	}

	testCases := []struct {
		Name             string
		JWS              *jose.JSONWebSignature
		ExpectedAuthType jwsAuthType
		ExpectedResult   *probs.ProblemDetails
		ErrorStatType    string
	}{
		{
			Name:             "Key ID and embedded JWS",
			JWS:              conflictJWS,
			ExpectedAuthType: invalidAuthType,
			ExpectedResult: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "jwk and kid header fields are mutually exclusive",
				HTTPStatus: http.StatusBadRequest,
			},
			ErrorStatType: "JWSAuthTypeInvalid",
		},
		{
			Name:             "Key ID when expected is embedded JWK",
			JWS:              testKeyIDJWS,
			ExpectedAuthType: embeddedJWK,
			ExpectedResult: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "No embedded JWK in JWS header",
				HTTPStatus: http.StatusBadRequest,
			},
			ErrorStatType: "JWSAuthTypeWrong",
		},
		{
			Name:             "Embedded JWK when expected is Key ID",
			JWS:              testEmbeddedJWS,
			ExpectedAuthType: embeddedKeyID,
			ExpectedResult: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "No Key ID in JWS header",
				HTTPStatus: http.StatusBadRequest,
			},
			ErrorStatType: "JWSAuthTypeWrong",
		},
		{
			Name:             "Key ID when expected is KeyID",
			JWS:              testKeyIDJWS,
			ExpectedAuthType: embeddedKeyID,
			ExpectedResult:   nil,
		},
		{
			Name:             "Embedded JWK when expected is embedded JWK",
			JWS:              testEmbeddedJWS,
			ExpectedAuthType: embeddedJWK,
			ExpectedResult:   nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			wfe.stats.joseErrorCount.Reset()
			prob := wfe.enforceJWSAuthType(tc.JWS, tc.ExpectedAuthType)
			if tc.ExpectedResult == nil && prob != nil {
				t.Fatalf("Expected nil result, got %#v", prob)
			} else {
				test.AssertMarshaledEquals(t, prob, tc.ExpectedResult)
			}
			if tc.ErrorStatType != "" {
				test.AssertMetricWithLabelsEquals(
					t, wfe.stats.joseErrorCount, prometheus.Labels{"type": tc.ErrorStatType}, 1)
			}
		})
	}
}

type badNonceProvider struct {
}

func (badNonceProvider) Nonce() (string, error) {
	return "im-a-nonce", nil
}

func TestValidNonce(t *testing.T) {
	wfe, _ := setupWFE(t)

	// signRequestEmbed with a `nil` nonce.NonceService will result in the
	// JWS not having a protected nonce header.
	missingNonceJWS, _, _ := signRequestEmbed(t, nil, "", "", nil)

	// signRequestEmbed with a badNonceProvider will result in the JWS
	// having an invalid nonce
	invalidNonceJWS, _, _ := signRequestEmbed(t, nil, "", "", badNonceProvider{})

	goodJWS, _, _ := signRequestEmbed(t, nil, "", "", wfe.nonceService)

	testCases := []struct {
		Name           string
		JWS            *jose.JSONWebSignature
		ExpectedResult *probs.ProblemDetails
		ErrorStatType  string
	}{
		{
			Name: "No nonce in JWS",
			JWS:  missingNonceJWS,
			ExpectedResult: &probs.ProblemDetails{
				Type:       probs.BadNonceProblem,
				Detail:     "JWS has no anti-replay nonce",
				HTTPStatus: http.StatusBadRequest,
			},
			ErrorStatType: "JWSMissingNonce",
		},
		{
			Name: "Invalid nonce in JWS",
			JWS:  invalidNonceJWS,
			ExpectedResult: &probs.ProblemDetails{
				Type:       probs.BadNonceProblem,
				Detail:     "JWS has an invalid anti-replay nonce: \"im-a-nonce\"",
				HTTPStatus: http.StatusBadRequest,
			},
			ErrorStatType: "JWSInvalidNonce",
		},
		{
			Name:           "Valid nonce in JWS",
			JWS:            goodJWS,
			ExpectedResult: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			wfe.stats.joseErrorCount.Reset()
			prob := wfe.validNonce(context.Background(), tc.JWS)
			if tc.ExpectedResult == nil && prob != nil {
				t.Fatalf("Expected nil result, got %#v", prob)
			} else {
				test.AssertMarshaledEquals(t, prob, tc.ExpectedResult)
			}
			if tc.ErrorStatType != "" {
				test.AssertMetricWithLabelsEquals(
					t, wfe.stats.joseErrorCount, prometheus.Labels{"type": tc.ErrorStatType}, 1)
			}
		})
	}
}

func signExtraHeaders(
	t *testing.T,
	headers map[jose.HeaderKey]interface{},
	nonceService jose.NonceSource) (*jose.JSONWebSignature, string) {
	privateKey := loadKey(t, []byte(test1KeyPrivatePEM))

	signerKey := jose.SigningKey{
		Key:       privateKey,
		Algorithm: sigAlgForKey(t, privateKey.Public()),
	}

	opts := &jose.SignerOptions{
		NonceSource:  nonceService,
		EmbedJWK:     true,
		ExtraHeaders: headers,
	}

	signer, err := jose.NewSigner(signerKey, opts)
	test.AssertNotError(t, err, "Failed to make signer")

	jws, err := signer.Sign([]byte(""))
	test.AssertNotError(t, err, "Failed to sign req")

	body := jws.FullSerialize()
	parsedJWS, err := jose.ParseSigned(body)
	test.AssertNotError(t, err, "Failed to parse generated JWS")

	return parsedJWS, body
}

func TestValidPOSTURL(t *testing.T) {
	wfe, _ := setupWFE(t)

	// A JWS and HTTP request with no extra headers
	noHeadersJWS, noHeadersJWSBody := signExtraHeaders(t, nil, wfe.nonceService)
	noHeadersRequest := makePostRequestWithPath("test-path", noHeadersJWSBody)

	// A JWS and HTTP request with extra headers, but no "url" extra header
	noURLHeaders := map[jose.HeaderKey]interface{}{
		"nifty": "swell",
	}
	noURLHeaderJWS, noURLHeaderJWSBody := signExtraHeaders(t, noURLHeaders, wfe.nonceService)
	noURLHeaderRequest := makePostRequestWithPath("test-path", noURLHeaderJWSBody)

	// A JWS and HTTP request with a mismatched HTTP URL to JWS "url" header
	wrongURLHeaders := map[jose.HeaderKey]interface{}{
		"url": "foobar",
	}
	wrongURLHeaderJWS, wrongURLHeaderJWSBody := signExtraHeaders(t, wrongURLHeaders, wfe.nonceService)
	wrongURLHeaderRequest := makePostRequestWithPath("test-path", wrongURLHeaderJWSBody)

	correctURLHeaderJWS, _, correctURLHeaderJWSBody := signRequestEmbed(t, nil, "http://localhost/test-path", "", wfe.nonceService)
	correctURLHeaderRequest := makePostRequestWithPath("test-path", correctURLHeaderJWSBody)

	testCases := []struct {
		Name           string
		JWS            *jose.JSONWebSignature
		Request        *http.Request
		ExpectedResult *probs.ProblemDetails
		ErrorStatType  string
	}{
		{
			Name:    "No extra headers in JWS",
			JWS:     noHeadersJWS,
			Request: noHeadersRequest,
			ExpectedResult: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "JWS header parameter 'url' required",
				HTTPStatus: http.StatusBadRequest,
			},
			ErrorStatType: "JWSNoExtraHeaders",
		},
		{
			Name:    "No URL header in JWS",
			JWS:     noURLHeaderJWS,
			Request: noURLHeaderRequest,
			ExpectedResult: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "JWS header parameter 'url' required",
				HTTPStatus: http.StatusBadRequest,
			},
			ErrorStatType: "JWSMissingURL",
		},
		{
			Name:    "Wrong URL header in JWS",
			JWS:     wrongURLHeaderJWS,
			Request: wrongURLHeaderRequest,
			ExpectedResult: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "JWS header parameter 'url' incorrect. Expected \"http://localhost/test-path\" got \"foobar\"",
				HTTPStatus: http.StatusBadRequest,
			},
			ErrorStatType: "JWSMismatchedURL",
		},
		{
			Name:           "Correct URL header in JWS",
			JWS:            correctURLHeaderJWS,
			Request:        correctURLHeaderRequest,
			ExpectedResult: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			tc.Request.Header.Add("Content-Type", expectedJWSContentType)
			wfe.stats.joseErrorCount.Reset()
			prob := wfe.validPOSTURL(tc.Request, tc.JWS)
			if tc.ExpectedResult == nil && prob != nil {
				t.Fatalf("Expected nil result, got %#v", prob)
			} else {
				test.AssertMarshaledEquals(t, prob, tc.ExpectedResult)
			}
			if tc.ErrorStatType != "" {
				test.AssertMetricWithLabelsEquals(
					t, wfe.stats.joseErrorCount, prometheus.Labels{"type": tc.ErrorStatType}, 1)
			}
		})
	}
}

func multiSigJWS(t *testing.T, nonceService jose.NonceSource) (*jose.JSONWebSignature, string) {
	privateKeyA := loadKey(t, []byte(test1KeyPrivatePEM))
	privateKeyB := loadKey(t, []byte(test2KeyPrivatePEM))

	signerKeyA := jose.SigningKey{
		Key:       privateKeyA,
		Algorithm: sigAlgForKey(t, privateKeyA.Public()),
	}

	signerKeyB := jose.SigningKey{
		Key:       privateKeyB,
		Algorithm: sigAlgForKey(t, privateKeyB.Public()),
	}

	opts := &jose.SignerOptions{
		NonceSource: nonceService,
		EmbedJWK:    true,
	}

	signer, err := jose.NewMultiSigner([]jose.SigningKey{signerKeyA, signerKeyB}, opts)
	test.AssertNotError(t, err, "Failed to make multi signer")

	jws, err := signer.Sign([]byte(""))
	test.AssertNotError(t, err, "Failed to sign req")

	body := jws.FullSerialize()
	parsedJWS, err := jose.ParseSigned(body)
	test.AssertNotError(t, err, "Failed to parse generated JWS")

	return parsedJWS, body
}

func TestParseJWSRequest(t *testing.T) {
	wfe, _ := setupWFE(t)

	_, tooManySigsJWSBody := multiSigJWS(t, wfe.nonceService)

	_, _, validJWSBody := signRequestEmbed(t, nil, "http://localhost/test-path", "", wfe.nonceService)
	validJWSRequest := makePostRequestWithPath("test-path", validJWSBody)

	missingSigsJWSBody := `{"payload":"Zm9x","protected":"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoicW5BUkxyVDdYejRnUmNLeUxkeWRtQ3ItZXk5T3VQSW1YNFg0MHRoazNvbjI2RmtNem5SM2ZSanM2NmVMSzdtbVBjQlo2dU9Kc2VVUlU2d0FhWk5tZW1vWXgxZE12cXZXV0l5aVFsZUhTRDdROHZCcmhSNnVJb080akF6SlpSLUNoelp1U0R0N2lITi0zeFVWc3B1NVhHd1hVX01WSlpzaFR3cDRUYUZ4NWVsSElUX09iblR2VE9VM1hoaXNoMDdBYmdaS21Xc1ZiWGg1cy1DcklpY1U0T2V4SlBndW5XWl9ZSkp1ZU9LbVR2bkxsVFY0TXpLUjJvWmxCS1oyN1MwLVNmZFZfUUR4X3lkbGU1b01BeUtWdGxBVjM1Y3lQTUlzWU53Z1VHQkNkWV8yVXppNWVYMGxUYzdNUFJ3ejZxUjFraXAtaTU5VmNHY1VRZ3FIVjZGeXF3IiwiZSI6IkFRQUIifSwia2lkIjoiIiwibm9uY2UiOiJyNHpuenZQQUVwMDlDN1JwZUtYVHhvNkx3SGwxZVBVdmpGeXhOSE1hQnVvIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdC9hY21lL25ldy1yZWcifQ"}`
	missingSigsJWSRequest := makePostRequestWithPath("test-path", missingSigsJWSBody)

	unprotectedHeadersJWSBody := `
{
  "header": {
    "alg": "RS256",
    "kid": "unprotected key id"
  },
  "protected": "eyJub25jZSI6ICJibTl1WTJVIiwgInVybCI6ICJodHRwOi8vbG9jYWxob3N0L3Rlc3QiLCAia2lkIjogInRlc3RrZXkifQ", 
  "payload": "Zm9v",
  "signature": "PKWWclRsiHF4bm-nmpxDez6Y_3Mdtu263YeYklbGYt1EiMOLiKY_dr_EqhUUKAKEWysFLO-hQLXVU7kVkHeYWQFFOA18oFgcZgkSF2Pr3DNZrVj9e2gl0eZ2i2jk6X5GYPt1lIfok_DrL92wrxEKGcrmxqXXGm0JgP6Al2VGapKZK2HaYbCHoGvtzNmzUX9rC21sKewq5CquJRvTmvQp5bmU7Q9KeafGibFr0jl6IA3W5LBGgf6xftuUtEVEbKmKaKtaG7tXsQH1mIVOPUZZoLWz9sWJSFLmV0QSXm3ZHV0DrOhLfcADbOCoQBMeGdseBQZuUO541A3BEKGv2Aikjw"
}
`

	wrongSignaturesFieldJWSBody := `
{
  "protected": "eyJub25jZSI6ICJibTl1WTJVIiwgInVybCI6ICJodHRwOi8vbG9jYWxob3N0L3Rlc3QiLCAia2lkIjogInRlc3RrZXkifQ", 
  "payload": "Zm9v",
  "signatures": ["PKWWclRsiHF4bm-nmpxDez6Y_3Mdtu263YeYklbGYt1EiMOLiKY_dr_EqhUUKAKEWysFLO-hQLXVU7kVkHeYWQFFOA18oFgcZgkSF2Pr3DNZrVj9e2gl0eZ2i2jk6X5GYPt1lIfok_DrL92wrxEKGcrmxqXXGm0JgP6Al2VGapKZK2HaYbCHoGvtzNmzUX9rC21sKewq5CquJRvTmvQp5bmU7Q9KeafGibFr0jl6IA3W5LBGgf6xftuUtEVEbKmKaKtaG7tXsQH1mIVOPUZZoLWz9sWJSFLmV0QSXm3ZHV0DrOhLfcADbOCoQBMeGdseBQZuUO541A3BEKGv2Aikjw"]
}
`

	testCases := []struct {
		Name            string
		Request         *http.Request
		ExpectedProblem *probs.ProblemDetails
		ErrorStatType   string
	}{
		{
			Name: "Invalid POST request",
			// No Content-Length, something that validPOSTRequest should be flagging
			Request: &http.Request{
				Method: "POST",
				URL:    mustParseURL("/"),
			},
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "missing Content-Length header",
				HTTPStatus: http.StatusLengthRequired,
			},
		},
		{
			Name:    "Invalid JWS in POST body",
			Request: makePostRequestWithPath("test-path", `{`),
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "Parse error reading JWS",
				HTTPStatus: http.StatusBadRequest,
			},
			ErrorStatType: "JWSUnmarshalFailed",
		},
		{
			Name:    "Too few signatures in JWS",
			Request: missingSigsJWSRequest,
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "POST JWS not signed",
				HTTPStatus: http.StatusBadRequest,
			},
			ErrorStatType: "JWSEmptySignature",
		},
		{
			Name:    "Too many signatures in JWS",
			Request: makePostRequestWithPath("test-path", tooManySigsJWSBody),
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "JWS \"signatures\" field not allowed. Only the \"signature\" field should contain a signature",
				HTTPStatus: http.StatusBadRequest,
			},
			ErrorStatType: "JWSMultiSig",
		},
		{
			Name:    "Unprotected JWS headers",
			Request: makePostRequestWithPath("test-path", unprotectedHeadersJWSBody),
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "JWS \"header\" field not allowed. All headers must be in \"protected\" field",
				HTTPStatus: http.StatusBadRequest,
			},
			ErrorStatType: "JWSUnprotectedHeaders",
		},
		{
			Name:    "Unsupported signatures field in JWS",
			Request: makePostRequestWithPath("test-path", wrongSignaturesFieldJWSBody),
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "JWS \"signatures\" field not allowed. Only the \"signature\" field should contain a signature",
				HTTPStatus: http.StatusBadRequest,
			},
			ErrorStatType: "JWSMultiSig",
		},
		{
			Name:            "Valid JWS in POST request",
			Request:         validJWSRequest,
			ExpectedProblem: nil,
		},
		{
			Name: "POST body too large",
			Request: makePostRequestWithPath("test-path",
				fmt.Sprintf(`{"a":"%s"}`, strings.Repeat("a", 50000))),
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.UnauthorizedProblem,
				Detail:     "request body too large",
				HTTPStatus: http.StatusForbidden,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			wfe.stats.joseErrorCount.Reset()
			_, prob := wfe.parseJWSRequest(tc.Request)
			if tc.ExpectedProblem == nil && prob != nil {
				t.Fatalf("Expected nil problem, got %#v\n", prob)
			} else {
				test.AssertMarshaledEquals(t, prob, tc.ExpectedProblem)
			}
			if tc.ErrorStatType != "" {
				test.AssertMetricWithLabelsEquals(
					t, wfe.stats.joseErrorCount, prometheus.Labels{"type": tc.ErrorStatType}, 1)
			}
		})
	}
}

func TestExtractJWK(t *testing.T) {
	wfe, _ := setupWFE(t)

	keyIDJWS, _, _ := signRequestKeyID(t, 1, nil, "", "", wfe.nonceService)
	goodJWS, goodJWK, _ := signRequestEmbed(t, nil, "", "", wfe.nonceService)

	testCases := []struct {
		Name            string
		JWS             *jose.JSONWebSignature
		ExpectedKey     *jose.JSONWebKey
		ExpectedProblem *probs.ProblemDetails
	}{
		{
			Name: "JWS with wrong auth type (Key ID vs embedded JWK)",
			JWS:  keyIDJWS,
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "No embedded JWK in JWS header",
				HTTPStatus: http.StatusBadRequest,
			},
		},
		{
			Name:        "Valid JWS with embedded JWK",
			JWS:         goodJWS,
			ExpectedKey: goodJWK,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			jwk, prob := wfe.extractJWK(tc.JWS)
			if tc.ExpectedProblem == nil && prob != nil {
				t.Fatalf("Expected nil problem, got %#v\n", prob)
			} else if tc.ExpectedProblem == nil {
				test.AssertMarshaledEquals(t, jwk, tc.ExpectedKey)
			} else {
				test.AssertMarshaledEquals(t, prob, tc.ExpectedProblem)
			}
		})
	}
}

func signRequestSpecifyKeyID(t *testing.T, keyID string, nonceService jose.NonceSource) (*jose.JSONWebSignature, string) {
	privateKey := loadKey(t, []byte(test1KeyPrivatePEM))

	if keyID == "" {
		keyID = "this is an invalid non-numeric key ID"
	}

	jwk := &jose.JSONWebKey{
		Key:       privateKey,
		Algorithm: "RSA",
		KeyID:     keyID,
	}

	signerKey := jose.SigningKey{
		Key:       jwk,
		Algorithm: jose.RS256,
	}

	opts := &jose.SignerOptions{
		NonceSource: nonceService,
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": "http://localhost",
		},
	}

	signer, err := jose.NewSigner(signerKey, opts)
	test.AssertNotError(t, err, "Failed to make signer")

	jws, err := signer.Sign([]byte(""))
	test.AssertNotError(t, err, "Failed to sign req")

	body := jws.FullSerialize()
	parsedJWS, err := jose.ParseSigned(body)
	test.AssertNotError(t, err, "Failed to parse generated JWS")

	return parsedJWS, body
}

func TestLookupJWK(t *testing.T) {
	wfe, _ := setupWFE(t)

	embeddedJWS, _, embeddedJWSBody := signRequestEmbed(t, nil, "", "", wfe.nonceService)
	invalidKeyIDJWS, invalidKeyIDJWSBody := signRequestSpecifyKeyID(t, "https://acme-99.lettuceencrypt.org/acme/reg/1", wfe.nonceService)
	// ID 100 is mocked to return a non-missing error from sa.GetRegistration
	errorIDJWS, _, errorIDJWSBody := signRequestKeyID(t, 100, nil, "", "", wfe.nonceService)
	// ID 102 is mocked to return an account does not exist error from sa.GetRegistration
	missingIDJWS, _, missingIDJWSBody := signRequestKeyID(t, 102, nil, "", "", wfe.nonceService)
	// ID 3 is mocked to return a deactivated account from sa.GetRegistration
	deactivatedIDJWS, _, deactivatedIDJWSBody := signRequestKeyID(t, 3, nil, "", "", wfe.nonceService)

	wfe.LegacyKeyIDPrefix = "https://acme-v00.lettuceencrypt.org/acme/reg/"
	legacyKeyIDJWS, legacyKeyIDJWSBody := signRequestSpecifyKeyID(t, wfe.LegacyKeyIDPrefix+"1", wfe.nonceService)

	nonNumericKeyIDJWS, nonNumericKeyIDJWSBody := signRequestSpecifyKeyID(t, wfe.LegacyKeyIDPrefix+"abcd", wfe.nonceService)

	validJWS, validKey, validJWSBody := signRequestKeyID(t, 1, nil, "", "", wfe.nonceService)
	validAccountPB, _ := wfe.sa.GetRegistration(context.Background(), &sapb.RegistrationID{Id: 1})
	validAccount, _ := bgrpc.PbToRegistration(validAccountPB)

	// good key, log event requester is set

	testCases := []struct {
		Name            string
		JWS             *jose.JSONWebSignature
		Request         *http.Request
		ExpectedProblem *probs.ProblemDetails
		ExpectedKey     *jose.JSONWebKey
		ExpectedAccount *core.Registration
		ErrorStatType   string
	}{
		{
			Name:    "JWS with wrong auth type (embedded JWK vs Key ID)",
			JWS:     embeddedJWS,
			Request: makePostRequestWithPath("test-path", embeddedJWSBody),
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "No Key ID in JWS header",
				HTTPStatus: http.StatusBadRequest,
			},
			ErrorStatType: "JWSAuthTypeWrong",
		},
		{
			Name:    "JWS with invalid key ID URL",
			JWS:     invalidKeyIDJWS,
			Request: makePostRequestWithPath("test-path", invalidKeyIDJWSBody),
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "KeyID header contained an invalid account URL: \"https://acme-99.lettuceencrypt.org/acme/reg/1\"",
				HTTPStatus: http.StatusBadRequest,
			},
			ErrorStatType: "JWSInvalidKeyID",
		},
		{
			Name:    "JWS with non-numeric account ID in key ID URL",
			JWS:     nonNumericKeyIDJWS,
			Request: makePostRequestWithPath("test-path", nonNumericKeyIDJWSBody),
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "Malformed account ID in KeyID header URL: \"https://acme-v00.lettuceencrypt.org/acme/reg/abcd\"",
				HTTPStatus: http.StatusBadRequest,
			},
			ErrorStatType: "JWSInvalidKeyID",
		},
		{
			Name:    "JWS with account ID that causes GetRegistration error",
			JWS:     errorIDJWS,
			Request: makePostRequestWithPath("test-path", errorIDJWSBody),
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.ServerInternalProblem,
				Detail:     "Error retrieving account \"http://localhost/acme/acct/100\"",
				HTTPStatus: http.StatusInternalServerError,
			},
			ErrorStatType: "JWSKeyIDLookupFailed",
		},
		{
			Name:    "JWS with account ID that doesn't exist",
			JWS:     missingIDJWS,
			Request: makePostRequestWithPath("test-path", missingIDJWSBody),
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.AccountDoesNotExistProblem,
				Detail:     "Account \"http://localhost/acme/acct/102\" not found",
				HTTPStatus: http.StatusBadRequest,
			},
			ErrorStatType: "JWSKeyIDNotFound",
		},
		{
			Name:    "JWS with account ID that is deactivated",
			JWS:     deactivatedIDJWS,
			Request: makePostRequestWithPath("test-path", deactivatedIDJWSBody),
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.UnauthorizedProblem,
				Detail:     "Account is not valid, has status \"deactivated\"",
				HTTPStatus: http.StatusForbidden,
			},
			ErrorStatType: "JWSKeyIDAccountInvalid",
		},
		{
			Name:            "Valid JWS with legacy account ID",
			JWS:             legacyKeyIDJWS,
			Request:         makePostRequestWithPath("test-path", legacyKeyIDJWSBody),
			ExpectedKey:     validKey,
			ExpectedAccount: &validAccount,
		},
		{
			Name:            "Valid JWS with valid account ID",
			JWS:             validJWS,
			Request:         makePostRequestWithPath("test-path", validJWSBody),
			ExpectedKey:     validKey,
			ExpectedAccount: &validAccount,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			wfe.stats.joseErrorCount.Reset()
			inputLogEvent := newRequestEvent()
			jwk, acct, prob := wfe.lookupJWK(tc.JWS, context.Background(), tc.Request, inputLogEvent)
			if tc.ExpectedProblem == nil && prob != nil {
				t.Fatalf("Expected nil problem, got %#v\n", prob)
			} else if tc.ExpectedProblem == nil {
				inThumb, _ := tc.ExpectedKey.Thumbprint(crypto.SHA256)
				outThumb, _ := jwk.Thumbprint(crypto.SHA256)
				test.AssertDeepEquals(t, inThumb, outThumb)
				test.AssertMarshaledEquals(t, acct, tc.ExpectedAccount)
				test.AssertEquals(t, inputLogEvent.Requester, acct.ID)
				test.AssertEquals(t, fmt.Sprint(inputLogEvent.Contacts), fmt.Sprint(*acct.Contact))
			} else {
				test.AssertMarshaledEquals(t, prob, tc.ExpectedProblem)
			}
			if tc.ErrorStatType != "" {
				test.AssertMetricWithLabelsEquals(
					t, wfe.stats.joseErrorCount, prometheus.Labels{"type": tc.ErrorStatType}, 1)
			}
		})
	}
}

func TestValidJWSForKey(t *testing.T) {
	wfe, _ := setupWFE(t)

	payload := `{ "test": "payload" }`
	testURL := "http://localhost/test"
	goodJWS, goodJWK, _ := signRequestEmbed(t, nil, testURL, payload, wfe.nonceService)

	// badSigJWSBody is a JWS that has had the payload changed by 1 byte to break the signature
	badSigJWSBody := `{"payload":"Zm9x","protected":"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoicW5BUkxyVDdYejRnUmNLeUxkeWRtQ3ItZXk5T3VQSW1YNFg0MHRoazNvbjI2RmtNem5SM2ZSanM2NmVMSzdtbVBjQlo2dU9Kc2VVUlU2d0FhWk5tZW1vWXgxZE12cXZXV0l5aVFsZUhTRDdROHZCcmhSNnVJb080akF6SlpSLUNoelp1U0R0N2lITi0zeFVWc3B1NVhHd1hVX01WSlpzaFR3cDRUYUZ4NWVsSElUX09iblR2VE9VM1hoaXNoMDdBYmdaS21Xc1ZiWGg1cy1DcklpY1U0T2V4SlBndW5XWl9ZSkp1ZU9LbVR2bkxsVFY0TXpLUjJvWmxCS1oyN1MwLVNmZFZfUUR4X3lkbGU1b01BeUtWdGxBVjM1Y3lQTUlzWU53Z1VHQkNkWV8yVXppNWVYMGxUYzdNUFJ3ejZxUjFraXAtaTU5VmNHY1VRZ3FIVjZGeXF3IiwiZSI6IkFRQUIifSwia2lkIjoiIiwibm9uY2UiOiJyNHpuenZQQUVwMDlDN1JwZUtYVHhvNkx3SGwxZVBVdmpGeXhOSE1hQnVvIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdC9hY21lL25ldy1yZWcifQ","signature":"jcTdxSygm_cvD7KbXqsxgnoPApCTSkV4jolToSOd2ciRkg5W7Yl0ZKEEKwOc-dYIbQiwGiDzisyPCicwWsOUA1WSqHylKvZ3nxSMc6KtwJCW2DaOqcf0EEjy5VjiZJUrOt2c-r6b07tbn8sfOJKwlF2lsOeGi4s-rtvvkeQpAU-AWauzl9G4bv2nDUeCviAZjHx_PoUC-f9GmZhYrbDzAvXZ859ktM6RmMeD0OqPN7bhAeju2j9Gl0lnryZMtq2m0J2m1ucenQBL1g4ZkP1JiJvzd2cAz5G7Ftl2YeJJyWhqNd3qq0GVOt1P11s8PTGNaSoM0iR9QfUxT9A6jxARtg"}`
	badJWS, err := jose.ParseSigned(badSigJWSBody)
	if err != nil {
		t.Fatal("error loading badSigJWS body")
	}

	// wrongAlgJWS is a JWS that has an invalid "HS256" algorithm in its header
	wrongAlgJWS := &jose.JSONWebSignature{
		Signatures: []jose.Signature{
			{
				Header: jose.Header{
					Algorithm: "HS256",
				},
			},
		},
	}

	// invalidNonceJWS uses the badNonceProvider from TestValidNonce to check
	// that JWS with a bad nonce value are rejected
	invalidNonceJWS, _, _ := signRequestEmbed(t, nil, "", "", badNonceProvider{})

	// A JWS and HTTP request with a mismatched HTTP URL to JWS "url" header
	wrongURLHeaders := map[jose.HeaderKey]interface{}{
		"url": "foobar",
	}
	wrongURLHeaderJWS, _ := signExtraHeaders(t, wrongURLHeaders, wfe.nonceService)

	// badJSONJWS has a valid signature over a body that is not valid JSON
	badJSONJWS, _, _ := signRequestEmbed(t, nil, testURL, `{`, wfe.nonceService)

	testCases := []struct {
		Name            string
		JWS             *jose.JSONWebSignature
		JWK             *jose.JSONWebKey
		Body            string
		ExpectedProblem *probs.ProblemDetails
		ErrorStatType   string
	}{
		{
			Name: "JWS with an invalid algorithm",
			JWS:  wrongAlgJWS,
			JWK:  goodJWK,
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.BadSignatureAlgorithmProblem,
				Detail:     "JWS signature header contains unsupported algorithm \"HS256\", expected one of RS256, ES256, ES384 or ES512",
				HTTPStatus: http.StatusBadRequest,
			},
			ErrorStatType: "JWSAlgorithmCheckFailed",
		},
		{
			Name: "JWS with an invalid nonce",
			JWS:  invalidNonceJWS,
			JWK:  goodJWK,
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.BadNonceProblem,
				Detail:     "JWS has an invalid anti-replay nonce: \"im-a-nonce\"",
				HTTPStatus: http.StatusBadRequest,
			},
			ErrorStatType: "JWSInvalidNonce",
		},
		{
			Name: "JWS with broken signature",
			JWS:  badJWS,
			JWK:  badJWS.Signatures[0].Header.JSONWebKey,
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "JWS verification error",
				HTTPStatus: http.StatusBadRequest,
			},
			ErrorStatType: "JWSVerifyFailed",
		},
		{
			Name: "JWS with incorrect URL",
			JWS:  wrongURLHeaderJWS,
			JWK:  wrongURLHeaderJWS.Signatures[0].Header.JSONWebKey,
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "JWS header parameter 'url' incorrect. Expected \"http://localhost/test\" got \"foobar\"",
				HTTPStatus: http.StatusBadRequest,
			},
			ErrorStatType: "JWSMismatchedURL",
		},
		{
			Name: "Valid JWS with invalid JSON in the protected body",
			JWS:  badJSONJWS,
			JWK:  goodJWK,
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "Request payload did not parse as JSON",
				HTTPStatus: http.StatusBadRequest,
			},
			ErrorStatType: "JWSBodyUnmarshalFailed",
		},
		{
			Name: "Good JWS and JWK",
			JWS:  goodJWS,
			JWK:  goodJWK,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			wfe.stats.joseErrorCount.Reset()
			inputLogEvent := newRequestEvent()
			request := makePostRequestWithPath("test", tc.Body)
			outPayload, prob := wfe.validJWSForKey(context.Background(), tc.JWS, tc.JWK, request, inputLogEvent)

			if tc.ExpectedProblem == nil && prob != nil {
				t.Fatalf("Expected nil problem, got %#v\n", prob)
			} else if tc.ExpectedProblem == nil {
				test.AssertEquals(t, inputLogEvent.Payload, payload)
				test.AssertEquals(t, string(outPayload), payload)
			} else {
				test.AssertMarshaledEquals(t, prob, tc.ExpectedProblem)
			}
			if tc.ErrorStatType != "" {
				test.AssertMetricWithLabelsEquals(
					t, wfe.stats.joseErrorCount, prometheus.Labels{"type": tc.ErrorStatType}, 1)
			}
		})
	}
}

func TestValidPOSTForAccount(t *testing.T) {
	wfe, _ := setupWFE(t)

	validJWS, _, validJWSBody := signRequestKeyID(t, 1, nil, "http://localhost/test", `{"test":"passed"}`, wfe.nonceService)
	validAccountPB, _ := wfe.sa.GetRegistration(context.Background(), &sapb.RegistrationID{Id: 1})
	validAccount, _ := bgrpc.PbToRegistration(validAccountPB)

	// ID 102 is mocked to return missing
	_, _, missingJWSBody := signRequestKeyID(t, 102, nil, "http://localhost/test", "{}", wfe.nonceService)

	// ID 3 is mocked to return deactivated
	key3 := loadKey(t, []byte(test3KeyPrivatePEM))
	_, _, deactivatedJWSBody := signRequestKeyID(t, 3, key3, "http://localhost/test", "{}", wfe.nonceService)

	_, _, embeddedJWSBody := signRequestEmbed(t, nil, "http://localhost/test", `{"test":"passed"}`, wfe.nonceService)

	testCases := []struct {
		Name            string
		Request         *http.Request
		ExpectedProblem *probs.ProblemDetails
		ExpectedPayload string
		ExpectedAcct    *core.Registration
		ExpectedJWS     *jose.JSONWebSignature
		ErrorStatType   string
	}{
		{
			Name:    "Invalid JWS",
			Request: makePostRequestWithPath("test", "foo"),
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "Parse error reading JWS",
				HTTPStatus: http.StatusBadRequest,
			},
			ErrorStatType: "JWSUnmarshalFailed",
		},
		{
			Name:    "Embedded Key JWS",
			Request: makePostRequestWithPath("test", embeddedJWSBody),
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "No Key ID in JWS header",
				HTTPStatus: http.StatusBadRequest,
			},
			ErrorStatType: "JWSAuthTypeWrong",
		},
		{
			Name:    "JWS signed by account that doesn't exist",
			Request: makePostRequestWithPath("test", missingJWSBody),
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.AccountDoesNotExistProblem,
				Detail:     "Account \"http://localhost/acme/acct/102\" not found",
				HTTPStatus: http.StatusBadRequest,
			},
			ErrorStatType: "JWSKeyIDNotFound",
		},
		{
			Name:    "JWS signed by account that's deactivated",
			Request: makePostRequestWithPath("test", deactivatedJWSBody),
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.UnauthorizedProblem,
				Detail:     "Account is not valid, has status \"deactivated\"",
				HTTPStatus: http.StatusForbidden,
			},
			ErrorStatType: "JWSKeyIDAccountInvalid",
		},
		{
			Name:            "Valid JWS for account",
			Request:         makePostRequestWithPath("test", validJWSBody),
			ExpectedPayload: `{"test":"passed"}`,
			ExpectedAcct:    &validAccount,
			ExpectedJWS:     validJWS,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			wfe.stats.joseErrorCount.Reset()
			inputLogEvent := newRequestEvent()
			outPayload, jws, acct, prob := wfe.validPOSTForAccount(tc.Request, context.Background(), inputLogEvent)
			if tc.ExpectedProblem == nil && prob != nil {
				t.Fatalf("Expected nil problem, got %#v\n", prob)
			} else if tc.ExpectedProblem == nil {
				test.AssertEquals(t, inputLogEvent.Payload, tc.ExpectedPayload)
				test.AssertEquals(t, string(outPayload), tc.ExpectedPayload)
				test.AssertMarshaledEquals(t, acct, tc.ExpectedAcct)
				test.AssertMarshaledEquals(t, jws, tc.ExpectedJWS)
			} else {
				test.AssertMarshaledEquals(t, prob, tc.ExpectedProblem)
			}
			if tc.ErrorStatType != "" {
				test.AssertMetricWithLabelsEquals(
					t, wfe.stats.joseErrorCount, prometheus.Labels{"type": tc.ErrorStatType}, 1)
			}
		})
	}
}

// TestValidPOSTAsGETForAccount tests POST-as-GET processing. Because
// wfe.validPOSTAsGETForAccount calls `wfe.validPOSTForAccount` to do all
// processing except the empty body test we do not duplicate the
// `TestValidPOSTForAccount` testcases here.
func TestValidPOSTAsGETForAccount(t *testing.T) {
	wfe, _ := setupWFE(t)

	// an invalid POST-as-GET request contains a non-empty payload. In this case
	// we test with the empty JSON payload ("{}")
	_, _, invalidPayloadRequest := signRequestKeyID(t, 1, nil, "http://localhost/test", "{}", wfe.nonceService)
	// a valid POST-as-GET request contains an empty payload.
	_, _, validRequest := signRequestKeyID(t, 1, nil, "http://localhost/test", "", wfe.nonceService)

	testCases := []struct {
		Name             string
		Request          *http.Request
		ExpectedProblem  *probs.ProblemDetails
		ExpectedLogEvent web.RequestEvent
	}{
		{
			Name:            "Non-empty JWS payload",
			Request:         makePostRequestWithPath("test", invalidPayloadRequest),
			ExpectedProblem: probs.Malformed("POST-as-GET requests must have an empty payload"),
			ExpectedLogEvent: web.RequestEvent{
				Contacts: []string{"mailto:person@mail.com"},
				Payload:  "{}",
			},
		},
		{
			Name:    "Valid POST-as-GET",
			Request: makePostRequestWithPath("test", validRequest),
			ExpectedLogEvent: web.RequestEvent{
				Contacts: []string{"mailto:person@mail.com"},
				Method:   "POST-as-GET",
			},
		},
	}

	for _, tc := range testCases {
		ev := newRequestEvent()
		_, prob := wfe.validPOSTAsGETForAccount(
			tc.Request,
			context.Background(),
			ev)
		if tc.ExpectedProblem == nil && prob != nil {
			t.Fatalf("Expected nil problem, got %#v\n", prob)
		} else if tc.ExpectedProblem != nil {
			test.AssertMarshaledEquals(t, prob, tc.ExpectedProblem)
		}
		test.AssertMarshaledEquals(t, *ev, tc.ExpectedLogEvent)
	}
}

type mockSADifferentStoredKey struct {
	sapb.StorageAuthorityGetterClient
}

// mockSADifferentStoredKey has a GetRegistration that will always return an
// account with the test 2 key, no matter the provided ID
func (sa mockSADifferentStoredKey) GetRegistration(_ context.Context, _ *sapb.RegistrationID, _ ...grpc.CallOption) (*corepb.Registration, error) {
	return &corepb.Registration{
		Key:    []byte(test2KeyPublicJSON),
		Status: string(core.StatusValid),
	}, nil
}

func TestValidPOSTForAccountSwappedKey(t *testing.T) {
	wfe, fc := setupWFE(t)
	wfe.sa = &mockSADifferentStoredKey{mocks.NewStorageAuthority(fc)}
	wfe.accountGetter = wfe.sa
	event := newRequestEvent()

	payload := `{"resource":"ima-payload"}`
	// Sign a request using test1key
	_, _, body := signRequestKeyID(t, 1, nil, "http://localhost:4001/test", payload, wfe.nonceService)
	request := makePostRequestWithPath("test", body)

	// Ensure that ValidPOSTForAccount produces an error since the
	// mockSADifferentStoredKey will return a different key than the one we used to
	// sign the request
	_, _, _, prob := wfe.validPOSTForAccount(request, ctx, event)
	test.Assert(t, prob != nil, "No error returned for request signed by wrong key")
	test.AssertEquals(t, prob.Type, probs.MalformedProblem)
	test.AssertEquals(t, prob.Detail, "JWS verification error")
}

func TestValidSelfAuthenticatedPOST(t *testing.T) {
	wfe, _ := setupWFE(t)

	_, validKey, validJWSBody := signRequestEmbed(t, nil, "http://localhost/test", `{"test":"passed"}`, wfe.nonceService)

	_, _, keyIDJWSBody := signRequestKeyID(t, 1, nil, "http://localhost/test", `{"test":"passed"}`, wfe.nonceService)

	testCases := []struct {
		Name            string
		Request         *http.Request
		ExpectedProblem *probs.ProblemDetails
		ExpectedPayload string
		ExpectedJWK     *jose.JSONWebKey
		ErrorStatType   string
	}{
		{
			Name:    "Invalid JWS",
			Request: makePostRequestWithPath("test", "foo"),
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "Parse error reading JWS",
				HTTPStatus: http.StatusBadRequest,
			},
			ErrorStatType: "JWSUnmarshalFailed",
		},
		{
			Name:    "JWS with key ID",
			Request: makePostRequestWithPath("test", keyIDJWSBody),
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "No embedded JWK in JWS header",
				HTTPStatus: http.StatusBadRequest,
			},
			ErrorStatType: "JWSAuthTypeWrong",
		},
		{
			Name:            "Valid JWS",
			Request:         makePostRequestWithPath("test", validJWSBody),
			ExpectedPayload: `{"test":"passed"}`,
			ExpectedJWK:     validKey,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			wfe.stats.joseErrorCount.Reset()
			inputLogEvent := newRequestEvent()
			outPayload, jwk, prob := wfe.validSelfAuthenticatedPOST(context.Background(), tc.Request, inputLogEvent)
			if tc.ExpectedProblem == nil && prob != nil {
				t.Fatalf("Expected nil problem, got %#v\n", prob)
			} else if tc.ExpectedProblem == nil {
				inThumb, _ := tc.ExpectedJWK.Thumbprint(crypto.SHA256)
				outThumb, _ := jwk.Thumbprint(crypto.SHA256)
				test.AssertDeepEquals(t, inThumb, outThumb)
				test.AssertEquals(t, inputLogEvent.Payload, tc.ExpectedPayload)
				test.AssertEquals(t, string(outPayload), tc.ExpectedPayload)
			} else {
				test.AssertMarshaledEquals(t, prob, tc.ExpectedProblem)
			}
			if tc.ErrorStatType != "" {
				test.AssertMetricWithLabelsEquals(
					t, wfe.stats.joseErrorCount, prometheus.Labels{"type": tc.ErrorStatType}, 1)
			}
		})
	}
}

func TestMatchJWSURLs(t *testing.T) {
	wfe, _ := setupWFE(t)

	noURLJWS, _, _ := signRequestEmbed(t, nil, "", "", wfe.nonceService)
	urlAJWS, _, _ := signRequestEmbed(t, nil, "example.com", "", wfe.nonceService)
	urlBJWS, _, _ := signRequestEmbed(t, nil, "example.org", "", wfe.nonceService)

	testCases := []struct {
		Name            string
		Outer           *jose.JSONWebSignature
		Inner           *jose.JSONWebSignature
		ExpectedProblem *probs.ProblemDetails
		ErrorStatType   string
	}{
		{
			Name:  "Outer JWS without URL",
			Outer: noURLJWS,
			Inner: urlAJWS,
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "Outer JWS header parameter 'url' required",
				HTTPStatus: http.StatusBadRequest,
			},
			ErrorStatType: "KeyRolloverOuterJWSNoURL",
		},
		{
			Name:  "Inner JWS without URL",
			Outer: urlAJWS,
			Inner: noURLJWS,
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "Inner JWS header parameter 'url' required",
				HTTPStatus: http.StatusBadRequest,
			},
			ErrorStatType: "KeyRolloverInnerJWSNoURL",
		},
		{
			Name:  "Inner and outer JWS without URL",
			Outer: noURLJWS,
			Inner: noURLJWS,
			ExpectedProblem: &probs.ProblemDetails{
				Type: probs.MalformedProblem,
				// The Outer JWS is validated first
				Detail:     "Outer JWS header parameter 'url' required",
				HTTPStatus: http.StatusBadRequest,
			},
			ErrorStatType: "KeyRolloverOuterJWSNoURL",
		},
		{
			Name:  "Mismatched inner and outer JWS URLs",
			Outer: urlAJWS,
			Inner: urlBJWS,
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "Outer JWS 'url' value \"example.com\" does not match inner JWS 'url' value \"example.org\"",
				HTTPStatus: http.StatusBadRequest,
			},
			ErrorStatType: "KeyRolloverMismatchedURLs",
		},
		{
			Name:  "Matching inner and outer JWS URLs",
			Outer: urlAJWS,
			Inner: urlAJWS,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			wfe.stats.joseErrorCount.Reset()
			prob := wfe.matchJWSURLs(tc.Outer, tc.Inner)
			if prob != nil && tc.ExpectedProblem == nil {
				t.Errorf("matchJWSURLs failed. Expected no problem, got %#v", prob)
			} else {
				test.AssertMarshaledEquals(t, prob, tc.ExpectedProblem)
			}
			if tc.ErrorStatType != "" {
				test.AssertMetricWithLabelsEquals(
					t, wfe.stats.joseErrorCount, prometheus.Labels{"type": tc.ErrorStatType}, 1)
			}
		})
	}
}
