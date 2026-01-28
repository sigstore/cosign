// Copyright 2022 the Sigstore Authors.
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

package verify

import (
	"context"
	"errors"
	"testing"

	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
)

func TestVerifyAttestationMissingSubject(t *testing.T) {
	ctx := context.Background()

	verifyAttestation := VerifyAttestationCommand{
		CertRef: "cert.pem",
		CertVerifyOptions: options.CertVerifyOptions{
			CertOidcIssuer: "issuer",
		},
	}

	err := verifyAttestation.Exec(ctx, []string{"foo", "bar", "baz"})
	if err == nil {
		t.Fatal("verifyAttestation expected 'need --certificate-identity'")
	}
}

func TestVerifyAttestationMissingIssuer(t *testing.T) {
	ctx := context.Background()

	verifyAttestation := VerifyAttestationCommand{
		CertRef: "cert.pem",
		CertVerifyOptions: options.CertVerifyOptions{
			CertIdentity: "subject",
		},
	}

	err := verifyAttestation.Exec(ctx, []string{"foo", "bar", "baz"})
	if err == nil {
		t.Fatal("verifyAttestation expected 'need --certificate-oidc-issuer'")
	}
}

func TestVerifyAttestationMutuallyExclusiveFlags(t *testing.T) {
	ctx := context.Background()
	tts := []struct {
		name          string
		cmd           VerifyAttestationCommand
		expectedError error
	}{
		{
			name: "both key and cert identity",
			cmd: VerifyAttestationCommand{
				KeyRef: "key.pub",
				CertVerifyOptions: options.CertVerifyOptions{
					CertIdentity: "hello@foo.com",
				},
			},
			expectedError: &options.KeyAndIdentityParseError{},
		},
		{
			name: "both key and cert identity regexp",
			cmd: VerifyAttestationCommand{
				KeyRef: "key.pub",
				CertVerifyOptions: options.CertVerifyOptions{
					CertIdentityRegexp: "^.*@foo.com$",
				},
			},
			expectedError: &options.KeyAndIdentityParseError{},
		},
		{
			name: "both cert identity and cert identity regexp",
			cmd: VerifyAttestationCommand{
				CertVerifyOptions: options.CertVerifyOptions{
					CertIdentity:       "hello@foo.com",
					CertIdentityRegexp: "^.*@foo.com$",
				},
			},
			expectedError: &options.KeyAndIdentityParseError{},
		},
		{
			name: "both key and security key",
			cmd: VerifyAttestationCommand{
				KeyRef: "key.pub",
				Sk:     true,
			},
			expectedError: &options.KeyParseError{},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Exec(ctx, []string{"foo", "bar", "baz"})
			if !errors.Is(err, tt.expectedError) {
				t.Fatalf("expected %T, got: %T, %v", tt.expectedError, err, err)
			}
		})
	}
}
