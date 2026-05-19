// Copyright 2026 The Sigstore Authors.
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

package bundle

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/signature"
)

func TestVerifierOptionsForKeypair(t *testing.T) {
	tests := []struct {
		name        string
		algorithm   protocommon.PublicKeyDetails
		privateKey  crypto.PrivateKey
		wantType    any
		expectEmpty bool
	}{
		{
			name:      "ed25519ph",
			algorithm: protocommon.PublicKeyDetails_PKIX_ED25519_PH,
			wantType:  &signature.ED25519phVerifier{},
		},
		{
			name:       "rsa-pss",
			algorithm:  protocommon.PublicKeyDetails_PKIX_RSA_PSS_2048_SHA256,
			privateKey: mustRSAKey(t),
			wantType:   &signature.RSAPSSVerifier{},
		},
		{
			name:        "default-ecdsa",
			algorithm:   protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
			expectEmpty: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keypair, err := sign.NewEphemeralKeypair(&sign.EphemeralKeypairOptions{Algorithm: tt.algorithm})
			if err != nil {
				t.Fatal(err)
			}
			opts := VerifierOptionsForKeypair(keypair)
			if tt.expectEmpty {
				if len(opts) != 0 {
					t.Fatalf("len(opts) = %d, want 0", len(opts))
				}
				return
			}

			pubKey := keypair.GetPublicKey()
			if tt.privateKey != nil {
				pubKey = tt.privateKey.(*rsa.PrivateKey).Public()
			}
			verifier, err := signature.LoadDefaultVerifier(pubKey, opts...)
			if err != nil {
				t.Fatal(err)
			}
			switch tt.wantType.(type) {
			case *signature.ED25519phVerifier:
				if _, ok := verifier.(*signature.ED25519phVerifier); !ok {
					t.Fatalf("verifier = %T, want *signature.ED25519phVerifier", verifier)
				}
			case *signature.RSAPSSVerifier:
				if _, ok := verifier.(*signature.RSAPSSVerifier); !ok {
					t.Fatalf("verifier = %T, want *signature.RSAPSSVerifier", verifier)
				}
			}
		})
	}
}

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
