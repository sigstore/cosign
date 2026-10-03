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
	"bytes"
	"context"
	"crypto/x509"
	"testing"

	"github.com/sigstore/cosign/v3/internal/test"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

func TestLocalCertChainProvider_GetCertificateChain(t *testing.T) {
	rootCert, rootKey, err := test.GenerateRootCa()
	if err != nil {
		t.Fatalf("GenerateRootCa: %v", err)
	}
	subCert, subKey, err := test.GenerateSubordinateCa(rootCert, rootKey)
	if err != nil {
		t.Fatalf("GenerateSubordinateCa: %v", err)
	}
	leafCert, _, err := test.GenerateLeafCert("subject@mail.com", "oidc-issuer", subCert, subKey)
	if err != nil {
		t.Fatalf("GenerateLeafCert: %v", err)
	}

	leafPEM, err := cryptoutils.MarshalCertificateToPEM(leafCert)
	if err != nil {
		t.Fatalf("MarshalCertificateToPEM: %v", err)
	}
	rootPEM, err := cryptoutils.MarshalCertificateToPEM(rootCert)
	if err != nil {
		t.Fatalf("MarshalCertificateToPEM: %v", err)
	}
	subAndRootPEM, err := cryptoutils.MarshalCertificatesToPEM([]*x509.Certificate{subCert, rootCert})
	if err != nil {
		t.Fatalf("MarshalCertificatesToPEM: %v", err)
	}
	leafSubAndRootPEM, err := cryptoutils.MarshalCertificatesToPEM([]*x509.Certificate{leafCert, subCert, rootCert})
	if err != nil {
		t.Fatalf("MarshalCertificatesToPEM: %v", err)
	}

	testCases := []struct {
		name      string
		cert      []byte
		chain     []byte
		wantDER   [][]byte
		wantError bool
	}{
		{
			name:    "leaf with root-only chain drops the self-signed root",
			cert:    leafPEM,
			chain:   rootPEM,
			wantDER: [][]byte{leafCert.Raw},
		},
		{
			name:    "leaf with sub and root chain drops the self-signed root",
			cert:    leafPEM,
			chain:   subAndRootPEM,
			wantDER: [][]byte{leafCert.Raw, subCert.Raw},
		},
		{
			name:    "leaf already present in chain is deduped and root is dropped",
			cert:    leafPEM,
			chain:   leafSubAndRootPEM,
			wantDER: [][]byte{leafCert.Raw, subCert.Raw},
		},
		{
			name:      "invalid leaf PEM",
			cert:      []byte("not a pem"),
			chain:     rootPEM,
			wantError: true,
		},
		{
			name:      "invalid chain PEM",
			cert:      leafPEM,
			chain:     []byte("not a pem"),
			wantError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider := &localCertChainProvider{cert: tc.cert, chain: tc.chain}
			got, err := provider.GetCertificateChain(context.Background(), nil, nil)
			if tc.wantError {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tc.wantDER) {
				t.Fatalf("expected %d certs, got %d", len(tc.wantDER), len(got))
			}
			for i := range got {
				if !bytes.Equal(got[i], tc.wantDER[i]) {
					t.Errorf("cert at index %d does not match expected DER", i)
				}
			}
		})
	}
}

// The bundle is verified against the signing key right after signing, so the
// verifier has to agree with the keypair about the signature scheme. Ed25519
// is the case where they can disagree: Ed25519ph and pure Ed25519 share a key
// and are not interchangeable.
func TestVerifierForKeypairMatchesTheSigningScheme(t *testing.T) {
	data := []byte("signed content")

	for _, algorithm := range []protocommon.PublicKeyDetails{
		protocommon.PublicKeyDetails_PKIX_ED25519_PH,
		protocommon.PublicKeyDetails_PKIX_ED25519,
		protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
	} {
		t.Run(algorithm.String(), func(t *testing.T) {
			keypair, err := sign.NewEphemeralKeypair(&sign.EphemeralKeypairOptions{Algorithm: algorithm})
			if err != nil {
				t.Fatalf("NewEphemeralKeypair: %v", err)
			}
			sig, _, err := keypair.SignData(context.Background(), data)
			if err != nil {
				t.Fatalf("SignData: %v", err)
			}

			verifier, err := verifierForKeypair(keypair, keypair.GetPublicKey())
			if err != nil {
				t.Fatalf("verifierForKeypair: %v", err)
			}
			if err := verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data)); err != nil {
				t.Fatalf("a verifier loaded for the keypair must accept its signature: %v", err)
			}
		})
	}
}

// Loading the verifier with the default options is exactly the mistake the
// helper exists to avoid; this pins the failure it would reintroduce.
func TestDefaultVerifierRejectsAnEd25519phSignature(t *testing.T) {
	keypair, err := sign.NewEphemeralKeypair(&sign.EphemeralKeypairOptions{Algorithm: protocommon.PublicKeyDetails_PKIX_ED25519_PH})
	if err != nil {
		t.Fatalf("NewEphemeralKeypair: %v", err)
	}
	data := []byte("signed content")
	sig, _, err := keypair.SignData(context.Background(), data)
	if err != nil {
		t.Fatalf("SignData: %v", err)
	}
	verifier, err := signature.LoadDefaultVerifier(keypair.GetPublicKey())
	if err != nil {
		t.Fatalf("LoadDefaultVerifier: %v", err)
	}
	if err := verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data)); err == nil {
		t.Fatal("a pure Ed25519 verifier accepted an Ed25519ph signature; the helper is no longer needed")
	}
}
