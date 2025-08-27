//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fulcio

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/internal/test"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/fulcio/pkg/api"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

type testClient struct {
	payload  api.CertificateResponse
	rootResp api.RootResponse
	err      error
}

var _ api.LegacyClient = (*testClient)(nil)

func (p *testClient) SigningCert(cr api.CertificateRequest, token string) (*api.CertificateResponse, error) { //nolint: revive
	return &p.payload, p.err
}

func (p *testClient) RootCert() (*api.RootResponse, error) {
	return &p.rootResp, p.err
}

func TestGetCertForOauthID(t *testing.T) {
	testKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Could not generate ecdsa keypair for test: %v", err)
	}
	sv, err := signature.LoadECDSASignerVerifier(testKey, crypto.SHA256)
	if err != nil {
		t.Fatalf("Could not create a signer: %v", err)
	}

	testCases := []struct {
		desc string

		email           string
		accessToken     string
		tokenGetterErr  error
		idTokenEmailErr error

		signingCertErr error

		expectErr bool
	}{{
		desc:  "happy case",
		email: "example@oidc.id",
		// Generated from https://justtrustme.dev/token?sub=test
		accessToken: "eyJhbGciOiJSUzI1NiIsImtpZCI6ImFhOWE1YjA5LTExMzktNGU2YS1hNjMxLTA2ZTU3NDU4NzI0MSJ9.eyJleHAiOjE3NTQwMjk5ODcsImlhdCI6MTc1NDAyODE4NywiaXNzIjoiaHR0cHM6Ly9qdXN0dHJ1c3RtZS5kZXYiLCJzdWIiOiJ0ZXN0In0.Fyp07QRXbuK65WKVKE6S7UgB9hvmNeyqWvcCWUvhMAwHwHl9EoRNwE-a5uBXgBgLUfbOCBHfc9fBIEEayzR1dRgfUXouOSIiZYr3DZNyGLdSiptL7wQRNy4rEiW44XCYFcbOuiWaii8icQUnOUO_TehgZHqSDvBSNQZcW-Rtx4A1us-CfVtrjqSNj_d0lCNEZ-vpL-Wp7JkOKzR0bN2KzYhVYHRe-pmvrzMWFfI17khB4wE6wj3e_PjDHAKS1EqGRrIgbr5jFcv9iGaf0zTnyZ_fxCmQM2Xe1u3kFlcCS0HondSJkxQoZRnK_OZHujNyWBT6cONg7Wvclkco3LulRw",
	}, {
		desc:  "SigningCert error",
		email: "example@oidc.id",
		// Generated from https://justtrustme.dev/token?sub=test
		accessToken:    "eyJhbGciOiJSUzI1NiIsImtpZCI6ImFhOWE1YjA5LTExMzktNGU2YS1hNjMxLTA2ZTU3NDU4NzI0MSJ9.eyJleHAiOjE3NTQwMjk5NTMsImlhdCI6MTc1NDAyODE1MywiaXNzIjoiaHR0cHM6Ly9qdXN0dHJ1c3RtZS5kZXYifQ.n2JrybZ64bCeSvVVPYIEf2x9aZM-Xxwzdkq_DcPuPJuwEINFJBRiOsJ6R6MllV0YodQkshFB81YOQ4_QC5h5lfDmr-fmvxcIPw0Iw1oQkiNl73BpiWmT63dQ7DxPPnfCPW9xPmo3j8BTJ8zKNPXTyfwGEHjv6rJ56bMjRDNR0W78vG8di9R8ZCAPD7WOwWfFW4JTYrgNnsSfiTmFWl8Z5iYBnkEBCaEWldpgOuUhofQ_jdG_UbLyY3iXkOmfseKCOnYiWzp0CYbU5EYC8RHk4SfZ5JvG7rv7JPmPw2IFQdTjObX9vY6vLvP2-nMj_7hAUbBWzci9bQOAx-W7usd4qA",
		signingCertErr: errors.New("SigningCert() failed"),
		expectErr:      true,
	}}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			expectedCertPem := &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: []byte("d34db33fd34db33fd34db33fd34db33f"),
			}
			expectedCertBytes := pem.EncodeToMemory(expectedCertPem)
			expectedExtraBytes := []byte("0123456789abcdef")
			tscp := &testClient{
				payload: api.CertificateResponse{
					CertPEM:  expectedCertBytes,
					ChainPEM: expectedExtraBytes,
				},
				err: tc.signingCertErr,
			}

			resp, err := GetCert(context.TODO(), sv, tc.accessToken, "token", "", "", "", "", tscp)
			if err != nil {
				if !tc.expectErr {
					t.Fatalf("getCertForOauthID returned error: %v", err)
				}
				return
			}
			if tc.expectErr {
				t.Fatalf("getCertForOauthID got: %q, %q wanted error", resp.CertPEM, resp.ChainPEM)
			}

			expectedCert := string(expectedCertBytes)
			actualCert := string(resp.CertPEM)
			if actualCert != expectedCert {
				t.Errorf("getCertForOauthID returned cert %q, wanted %q", actualCert, expectedCert)
			}
			expectedChain := string(expectedExtraBytes)
			actualChain := string(resp.ChainPEM)
			if actualChain != expectedChain {
				t.Errorf("getCertForOauthID returned chain %q, wanted %q", actualChain, expectedChain)
			}
		})
	}
}

func TestNewClient(t *testing.T) {
	t.Parallel()
	expectedUserAgent := options.UserAgent()
	requestReceived := false
	testServer := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			requestReceived = true
			file := []byte{}

			got := r.UserAgent()
			if got != expectedUserAgent {
				t.Errorf("wanted User-Agent %q, got %q", expectedUserAgent, got)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(file)
		}))
	defer testServer.Close()

	client, err := NewClient(testServer.URL)
	if err != nil {
		t.Error(err)
	}

	_, _ = client.SigningCert(api.CertificateRequest{}, "")

	if !requestReceived {
		t.Fatal("no requests were received")
	}
}

func TestNewSigner(t *testing.T) {
	rootCert, rootKey, _ := test.GenerateRootCa()
	leafCert, _, _ := test.GenerateLeafCert("subject", "oidc-issuer", rootCert, rootKey)
	pemChain, _ := cryptoutils.MarshalCertificatesToPEM([]*x509.Certificate{leafCert, rootCert})

	testServer := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write(pemChain)
		}))
	defer testServer.Close()

	// success: Generate a random key and create a corresponding
	// SignerVerifier.
	ctx := context.TODO()
	ko := options.KeyOpts{
		OIDCDisableProviders: true,
		// Generated from https://justtrustme.dev/token?sub=test
		IDToken:        "eyJhbGciOiJSUzI1NiIsImtpZCI6ImFhOWE1YjA5LTExMzktNGU2YS1hNjMxLTA2ZTU3NDU4NzI0MSJ9.eyJleHAiOjE3NTQwMjk5ODcsImlhdCI6MTc1NDAyODE4NywiaXNzIjoiaHR0cHM6Ly9qdXN0dHJ1c3RtZS5kZXYiLCJzdWIiOiJ0ZXN0In0.Fyp07QRXbuK65WKVKE6S7UgB9hvmNeyqWvcCWUvhMAwHwHl9EoRNwE-a5uBXgBgLUfbOCBHfc9fBIEEayzR1dRgfUXouOSIiZYr3DZNyGLdSiptL7wQRNy4rEiW44XCYFcbOuiWaii8icQUnOUO_TehgZHqSDvBSNQZcW-Rtx4A1us-CfVtrjqSNj_d0lCNEZ-vpL-Wp7JkOKzR0bN2KzYhVYHRe-pmvrzMWFfI17khB4wE6wj3e_PjDHAKS1EqGRrIgbr5jFcv9iGaf0zTnyZ_fxCmQM2Xe1u3kFlcCS0HondSJkxQoZRnK_OZHujNyWBT6cONg7Wvclkco3LulRw",
		FulcioURL:      testServer.URL,
		FulcioAuthFlow: "token",
	}
	privKey, err := cosign.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	sv, err := signature.LoadECDSASignerVerifier(privKey, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewSigner(ctx, ko, sv)
	if err != nil {
		t.Fatalf("unexpected error creating signer: %v", err)
	}
	responsePEMChain := string(signer.Cert) + string(signer.Chain)
	if responsePEMChain != string(pemChain) {
		t.Fatalf("response certificates not equal, got %v, expected %v", responsePEMChain, pemChain)
	}
	if signer.SignerVerifier == nil {
		t.Fatalf("missing signer/verifier")
	}
}
