// Copyright 2025 The Sigstore Authors.
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

package key

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

// mockSignerVerifier is a mock implementation of signature.SignerVerifier for testing.
type mockSignerVerifier struct {
	pubKey    crypto.PublicKey
	pubKeyErr error
	signErr   error
}

func (m *mockSignerVerifier) PublicKey(_ ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	if m.pubKeyErr != nil {
		return nil, m.pubKeyErr
	}
	return m.pubKey, nil
}

func (m *mockSignerVerifier) SignMessage(_ io.Reader, _ ...signature.SignOption) ([]byte, error) {
	if m.signErr != nil {
		return nil, m.signErr
	}
	return []byte("mock-signature"), nil
}

func (m *mockSignerVerifier) VerifySignature(_, _ io.Reader, _ ...signature.VerifyOption) error {
	return errors.New("not implemented")
}

func TestNewKMSKeypair(t *testing.T) {
	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ecdsa key: %v", err)
	}
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}
	_, ed25519Priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}

	testCases := []struct {
		name      string
		sv        signature.SignerVerifier
		expectErr bool
		errMsg    string
	}{
		{
			name: "ECDSA key",
			sv: &mockSignerVerifier{
				pubKey: &ecdsaPriv.PublicKey,
			},
			expectErr: false,
		},
		{
			name: "RSA key",
			sv: &mockSignerVerifier{
				pubKey: &rsaPriv.PublicKey,
			},
			expectErr: false,
		},
		{
			name: "ED25519 key",
			sv: &mockSignerVerifier{
				pubKey: ed25519Priv.Public(),
			},
			expectErr: false,
		},
		{
			name: "Unsupported key type",
			sv: &mockSignerVerifier{
				pubKey: "not a key",
			},
			expectErr: true,
			errMsg:    "unsupported public key type",
		},
		{
			name: "PublicKey returns error",
			sv: &mockSignerVerifier{
				pubKeyErr: errors.New("pubkey error"),
			},
			expectErr: true,
			errMsg:    "getting public key: pubkey error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			kp, err := NewSignerVerifierKeypair(tc.sv, nil)
			if tc.expectErr {
				if err == nil {
					t.Errorf("expected an error, but got none")
				} else if !strings.Contains(err.Error(), tc.errMsg) {
					t.Errorf("expected error message '%s', got '%s'", tc.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if kp == nil {
					t.Error("expected a keypair, but got nil")
				}
			}
		})
	}
}

func TestKMSKeypair_Methods(t *testing.T) {
	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ecdsa key: %v", err)
	}
	sv := &mockSignerVerifier{pubKey: &ecdsaPriv.PublicKey}
	kp, err := NewSignerVerifierKeypair(sv, nil)
	if err != nil {
		t.Fatalf("failed to create KMSKeypair: %v", err)
	}

	t.Run("GetHashAlgorithm", func(t *testing.T) {
		if kp.GetHashAlgorithm() != protocommon.HashAlgorithm_SHA2_256 {
			t.Errorf("expected SHA2_256, got %v", kp.GetHashAlgorithm())
		}
	})

	t.Run("GetSigningAlgorithm", func(t *testing.T) {
		if kp.GetSigningAlgorithm() != protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256 {
			t.Errorf("expected ECDSA_P256_SHA256, got %v", kp.GetSigningAlgorithm())
		}
	})

	t.Run("GetHint", func(t *testing.T) {
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(&ecdsaPriv.PublicKey)
		if err != nil {
			t.Fatalf("marshalling public key: %v", err)
		}
		hashedBytes := sha256.Sum256(pubKeyBytes)
		expectedHint := base64.StdEncoding.EncodeToString(hashedBytes[:])

		if string(kp.GetHint()) != expectedHint {
			t.Errorf("expected hint %s, got %s", expectedHint, string(kp.GetHint()))
		}
	})

	t.Run("GetKeyAlgorithm", func(t *testing.T) {
		if kp.GetKeyAlgorithm() != "ECDSA" {
			t.Errorf("expected ECDSA, got %s", kp.GetKeyAlgorithm())
		}
	})

	t.Run("GetPublicKey", func(t *testing.T) {
		pub := kp.GetPublicKey()
		if !pub.(*ecdsa.PublicKey).Equal(&ecdsaPriv.PublicKey) {
			t.Error("public keys do not match")
		}
	})

	t.Run("GetPublicKeyPem", func(t *testing.T) {
		pem, err := kp.GetPublicKeyPem()
		if err != nil {
			t.Fatalf("GetPublicKeyPem returned an error: %v", err)
		}
		pub, err := cryptoutils.UnmarshalPEMToPublicKey([]byte(pem))
		if err != nil {
			t.Fatalf("failed to unmarshal pem: %v", err)
		}
		if !pub.(*ecdsa.PublicKey).Equal(&ecdsaPriv.PublicKey) {
			t.Error("public keys do not match")
		}
	})

	t.Run("SignData", func(t *testing.T) {
		data := []byte("some data to sign")
		sig, digest, err := kp.SignData(context.Background(), data)
		if err != nil {
			t.Fatalf("SignData returned an error: %v", err)
		}
		if string(sig) != "mock-signature" {
			t.Errorf("expected signature 'mock-signature', got '%s'", string(sig))
		}

		h := sha256.New()
		h.Write(data)
		expectedDigest := h.Sum(nil)
		if !bytes.Equal(digest, expectedDigest) {
			t.Errorf("expected digest %x, got %x", expectedDigest, digest)
		}
	})

	t.Run("SignData with error", func(t *testing.T) {
		errSV := &mockSignerVerifier{
			pubKey:  &ecdsaPriv.PublicKey,
			signErr: errors.New("signing failed"),
		}
		errKP, err := NewSignerVerifierKeypair(errSV, nil)
		if err != nil {
			t.Fatalf("failed to create KMSKeypair: %v", err)
		}

		_, _, err = errKP.SignData(context.Background(), []byte("data"))
		if err == nil {
			t.Error("expected an error, but got none")
		} else if err.Error() != "signing failed" {
			t.Errorf("expected error 'signing failed', got '%s'", err.Error())
		}
	})
}
