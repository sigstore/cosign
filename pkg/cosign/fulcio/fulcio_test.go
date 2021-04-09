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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/go-openapi/runtime"

	"github.com/sigstore/fulcio/pkg/generated/client/operations"
	"github.com/sigstore/sigstore/pkg/oauthflow"
)

type testFlow struct {
	idt   *oauthflow.OIDCIDToken
	email string
	err   error
}

func (tf *testFlow) OIDConnect(url, clientID, secret string) (*oauthflow.OIDCIDToken, string, error) {
	if tf.err != nil {
		return nil, "", tf.err
	}
	return tf.idt, tf.email, nil
}

type testSigningCertProvider struct {
	payload string
	err     error
}

func (p *testSigningCertProvider) SigningCert(params *operations.SigningCertParams, authInfo runtime.ClientAuthInfoWriter, opts ...operations.ClientOption) (*operations.SigningCertCreated, error) {
	return &operations.SigningCertCreated{
		Payload: p.payload,
	}, p.err
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
	}{
		{
			desc:        "happy case",
			email:       "example@oidc.id",
			accessToken: "abc123foobar",
		},
		{
			desc:           "getIDToken error",
			email:          "example@oidc.id",
			accessToken:    "abc123foobar",
			tokenGetterErr: errors.New("getIDToken() failed"),
			expectErr:      true,
		},
		{
			desc:           "SigningCert error",
			email:          "example@oidc.id",
			accessToken:    "abc123foobar",
			signingCertErr: errors.New("SigningCert() failed"),
			expectErr:      true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			expectedCertPem := &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: []byte("d34db33fd34db33fd34db33fd34db33f"),
			}
			expectedCertBytes := pem.EncodeToMemory(expectedCertPem)
			expectedExtraBytes := []byte("0123456789abcdef")
			tscp := &testSigningCertProvider{
				payload: string(append(expectedCertBytes, expectedExtraBytes...)),
				err:     tc.signingCertErr,
			}

			tf := testFlow{
				email: tc.email,
				idt: &oauthflow.OIDCIDToken{
					RawString: tc.accessToken,
				},
				err: tc.tokenGetterErr,
			}

			cert, chain, err := getCertForOauthID(testKey, tscp, &tf)

			if err != nil {
				if !tc.expectErr {
					t.Fatalf("getCertForOauthID returned error: %v", err)
				}
				return
			}
			if tc.expectErr {
				t.Fatalf("getCertForOauthID got: %q, %q wanted error", cert, chain)
			}

			expectedCert := string(expectedCertBytes)
			if cert != expectedCert {
				t.Errorf("getCertForOauthID returned cert %q, wanted %q", cert, expectedCert)
			}
			expectedChain := string(expectedExtraBytes)
			if chain != expectedChain {
				t.Errorf("getCertForOauthID returned chain %q, wanted %q", chain, expectedChain)
			}
		})
	}
}
