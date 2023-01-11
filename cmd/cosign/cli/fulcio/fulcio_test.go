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
	"os"
	"path/filepath"
	"testing"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/test"
	"github.com/sigstore/fulcio/pkg/api"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"github.com/sigstore/sigstore/pkg/signature"
)

type testFlow struct {
	idt   *oauthflow.OIDCIDToken
	email string
	err   error
}

func (tf *testFlow) OIDConnect(url, clientID, secret, redirectURL string) (*oauthflow.OIDCIDToken, error) {
	if tf.err != nil {
		return nil, tf.err
	}
	return tf.idt, nil
}

type testClient struct {
	payload  api.CertificateResponse
	rootResp api.RootResponse
	err      error
}

var _ api.LegacyClient = (*testClient)(nil)

func (p *testClient) SigningCert(cr api.CertificateRequest, token string) (*api.CertificateResponse, error) {
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
		desc:        "happy case",
		email:       "example@oidc.id",
		accessToken: "abc123foobar",
	}, {
		desc:           "getIDToken error",
		email:          "example@oidc.id",
		accessToken:    "abc123foobar",
		tokenGetterErr: errors.New("getIDToken() failed"),
		expectErr:      true,
	}, {
		desc:           "SigningCert error",
		email:          "example@oidc.id",
		accessToken:    "abc123foobar",
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

			tf := testFlow{
				email: tc.email,
				idt: &oauthflow.OIDCIDToken{
					RawString: tc.accessToken,
				},
				err: tc.tokenGetterErr,
			}

			resp, err := getCertForOauthID(sv, tscp, &tf, "", "", "", "")

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
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write(pemChain)
		}))
	defer testServer.Close()

	// success: a random key is generated
	ctx := context.TODO()
	ko := options.KeyOpts{
		OIDCDisableProviders: true,
		// random test token
		IDToken:        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
		FulcioURL:      testServer.URL,
		FulcioAuthFlow: "token",
	}
	signer, err := NewSigner(ctx, ko)
	if err != nil {
		t.Fatalf("unexpected error creating signer: %v", err)
	}
	responsePEMChain := string(signer.Cert) + string(signer.Chain)
	if responsePEMChain != string(pemChain) {
		t.Fatalf("response certificates not equal, got %v, expected %v", responsePEMChain, pemChain)
	}
	// check that a key was generated
	if signer.SignerVerifier == nil {
		t.Fatalf("missing signer/verifier")
	}

	// success: a key is used when provided
	// generate and persist key
	keys, err := cosign.GenerateKeyPair(nil)
	ecdsaKey, _ := cosign.LoadPrivateKey(keys.PrivateBytes, nil)
	if err != nil {
		t.Fatal(err)
	}
	// ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// privKeyBytes, _ := x509.MarshalPKCS8PrivateKey(ecdsaKey)
	// pemKey := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED COSIGN PRIVATE KEY", Bytes: privKeyBytes})
	td := t.TempDir()
	keyPath := filepath.Join(td, "key")
	if err := os.WriteFile(keyPath, keys.PrivateBytes, 0644); err != nil {
		t.Fatal(err)
	}
	// set required KeyOpts
	ko.IssueCertificate = true
	ko.KeyRef = keyPath
	ko.PassFunc = nil
	signer, err = NewSigner(ctx, ko)
	if err != nil {
		t.Fatalf("unexpected error creating signer: %v", err)
	}
	pubKey, _ := signer.SignerVerifier.PublicKey()
	expectedPubKey, _ := ecdsaKey.PublicKey()
	if err := cryptoutils.EqualKeys(expectedPubKey, pubKey); err != nil {
		t.Fatalf("keys are not equal: %v", err)
	}
}
