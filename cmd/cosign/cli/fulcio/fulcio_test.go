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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	fulciopb "github.com/sigstore/fulcio/pkg/generated/protobuf"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"google.golang.org/grpc"
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
	payload  fulciopb.SigningCertificate
	rootResp fulciopb.TrustBundle
	config   fulciopb.Configuration
	err      error
}

var _ fulciopb.CAClient = (*testClient)(nil)

func (p *testClient) CreateSigningCertificate(_ context.Context, _ *fulciopb.CreateSigningCertificateRequest, _ ...grpc.CallOption) (*fulciopb.SigningCertificate, error) {
	return &p.payload, p.err
}

func (p *testClient) GetTrustBundle(_ context.Context, _ *fulciopb.GetTrustBundleRequest, _ ...grpc.CallOption) (*fulciopb.TrustBundle, error) {
	return &p.rootResp, p.err
}

func (p *testClient) GetConfiguration(_ context.Context, _ *fulciopb.GetConfigurationRequest, _ ...grpc.CallOption) (*fulciopb.Configuration, error) {
	return &p.config, p.err
}

func TestGetCertForOauthID(t *testing.T) {
	testKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Could not generate ecdsa keypair for test: %v", err)
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
				payload: fulciopb.SigningCertificate{
					Certificate: &fulciopb.SigningCertificate_SignedCertificateDetachedSct{
						SignedCertificateDetachedSct: &fulciopb.SigningCertificateDetachedSCT{
							Chain: &fulciopb.CertificateChain{
								Certificates: []string{string(expectedCertBytes), string(expectedExtraBytes)},
							},
						},
					},
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

			resp, err := getCertForOauthID(context.Background(), testKey, tscp, &tf, "", "", "", "")
			if err != nil {
				if !tc.expectErr {
					t.Fatalf("getCertForOauthID returned error: %v", err)
				}
				return
			}

			leaf := resp.GetSignedCertificateDetachedSct().Chain.Certificates[0]
			extra := resp.GetSignedCertificateDetachedSct().Chain.Certificates[1]
			if tc.expectErr {
				t.Fatalf("getCertForOauthID got: %q, %q wanted error", leaf, extra)
			}

			expectedCert := string(expectedCertBytes)
			actualCert := leaf
			if actualCert != expectedCert {
				t.Errorf("getCertForOauthID returned cert %q, wanted %q", actualCert, expectedCert)
			}
			expectedChain := string(expectedExtraBytes)
			actualChain := extra
			if actualChain != expectedChain {
				t.Errorf("getCertForOauthID returned chain %q, wanted %q", actualChain, expectedChain)
			}
		})
	}
}

func TestNewClient(t *testing.T) {
	t.Parallel()
	requestReceived := false
	testServer := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			requestReceived = true
			file := []byte{}

			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(file)
		}))
	defer testServer.Close()

	client, err := NewClient(testServer.URL)
	if err != nil {
		t.Error(err)
	}

	_, _ = client.CreateSigningCertificate(context.Background(), &fulciopb.CreateSigningCertificateRequest{})

	if !requestReceived {
		t.Fatal("no requests were received")
	}
}
