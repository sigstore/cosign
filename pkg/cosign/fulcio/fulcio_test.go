/*
Copyright The Sigstore Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
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
)

type testIDToken struct {
	e, at    string
	emailErr error
}

func (tidt *testIDToken) email() (string, error) {
	return tidt.e, tidt.emailErr
}

func (tidt *testIDToken) accessToken() string {
	return tidt.at
}

type testTokenGetter struct {
	idt idToken
	err error
}

func (ttg *testTokenGetter) getIDToken() (idToken, error) {
	return ttg.idt, ttg.err
}

type testSigningCertProvider struct {
	payload string
	err     error
}

func (p *testSigningCertProvider) SigningCert(params *operations.SigningCertParams, authInfo runtime.ClientAuthInfoWriter) (*operations.SigningCertCreated, error) {
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
			desc:            "token.email() error",
			email:           "example@oidc.id",
			accessToken:     "abc123foobar",
			idTokenEmailErr: errors.New("token.email() failed"),
			expectErr:       true,
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
			tidt := &testIDToken{
				e:        tc.email,
				at:       tc.accessToken,
				emailErr: tc.idTokenEmailErr,
			}
			ttg := &testTokenGetter{
				idt: tidt,
				err: tc.tokenGetterErr,
			}
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

			cert, chain, err := getCertForOauthID(testKey, ttg, tscp)

			if err != nil {
				if !tc.expectErr {
					t.Fatalf("getCertForOauthID returned error: %v", err)
				}
				return
			}
			if tc.expectErr {
				t.Fatalf("getCertForOauthID got: %q, %q wanted and error", cert, chain)
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
