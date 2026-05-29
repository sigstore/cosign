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

package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
)

func TestParsePayloadDigest(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expectAlg string
		expectHex string
		expectErr bool
	}{
		{
			name:      "valid sha256 digest",
			input:     "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			expectAlg: "sha256",
			expectHex: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			expectErr: false,
		},
		{
			name:      "missing colon",
			input:     "sha256e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			expectErr: true,
		},
		{
			name:      "invalid hex digest",
			input:     "sha256:invalidhex",
			expectErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			alg, digest, err := parsePayloadDigest(tc.input)
			if tc.expectErr {
				if err == nil {
					t.Fatal("expected error but got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if alg != tc.expectAlg {
				t.Errorf("expected algorithm %q, got %q", tc.expectAlg, alg)
			}
			actualHex := hex.EncodeToString(digest)
			if actualHex != tc.expectHex {
				t.Errorf("expected digest hex %q, got %q", tc.expectHex, actualHex)
			}
		})
	}
}

func TestAttestationToPayloadJSON(t *testing.T) {
	makeMockPayload := func(predicateType string, innerPayload map[string]interface{}) []byte {
		statement := map[string]interface{}{
			"predicateType": predicateType,
		}
		statementBytes, _ := json.Marshal(statement)
		b64Statement := base64.StdEncoding.EncodeToString(statementBytes)

		envelope := map[string]interface{}{
			"payload":     b64Statement,
			"payloadType": "application/vnd.in-toto+json",
		}
		envelopeBytes, _ := json.Marshal(envelope)
		return envelopeBytes
	}

	tests := []struct {
		name          string
		predicateType string
		mockPayload   []byte
		expectType    string
		expectErr     bool
	}{
		{
			name:          "valid custom predicate type matching",
			predicateType: "custom",
			mockPayload:   makeMockPayload("https://cosign.sigstore.dev/attestation/v0.1", map[string]interface{}{"foo": "bar"}),
			expectType:    "https://cosign.sigstore.dev/attestation/v0.1",
			expectErr:     false,
		},
		{
			name:          "valid slsaprovenance predicate matching",
			predicateType: "slsaprovenance",
			mockPayload:   makeMockPayload("https://slsa.dev/provenance/v0.2", map[string]interface{}{}),
			expectType:    "https://slsa.dev/provenance/v0.2",
			expectErr:     false,
		},
		{
			name:          "mismatched predicate type",
			predicateType: "slsaprovenance",
			mockPayload:   makeMockPayload("https://slsa.dev/provenance/v1.0-mismatched", map[string]interface{}{}),
			expectType:    "https://slsa.dev/provenance/v1.0-mismatched",
			expectErr:     false,
		},
		{
			name:          "invalid envelope json",
			predicateType: "custom",
			mockPayload:   []byte("invalid-json"),
			expectErr:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, parsedType, err := attestationToPayloadJSON(context.Background(), tc.predicateType, tc.mockPayload)
			if tc.expectErr {
				if err == nil {
					t.Fatal("expected error but got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			expectedURI := predicateTypeMap[tc.predicateType]
			if expectedURI == "" {
				expectedURI = tc.predicateType
			}

			if parsedType != expectedURI && tc.expectType != parsedType {
				t.Errorf("expected parsed type %q, got %q", tc.expectType, parsedType)
			}

			if parsedType == expectedURI {
				if len(res) == 0 {
					t.Error("expected valid output payload but got empty")
				}
			} else {
				if len(res) != 0 {
					t.Errorf("expected empty payload due to type mismatch, got: %s", string(res))
				}
			}
		})
	}
}

func TestVerifyCmd(t *testing.T) {
	td := t.TempDir()

	// 1. Generate P-256 Key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes})
	pubKeyPath := filepath.Join(td, "key.pub")
	if err := os.WriteFile(pubKeyPath, pubPEM, 0644); err != nil {
		t.Fatal(err)
	}

	// 2. Write payload blob
	payload := []byte("hello-world-verification")
	payloadPath := filepath.Join(td, "payload.txt")
	if err := os.WriteFile(payloadPath, payload, 0644); err != nil {
		t.Fatal(err)
	}

	// 3. Sign payload to produce signature
	hash := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, privKey, hash[:])
	if err != nil {
		t.Fatal(err)
	}

	// 4. Construct standard Sigstore JSON bundle (v0.3 schema)
	bundleMap := map[string]interface{}{
		"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"verificationMaterial": map[string]interface{}{
			"publicKey": map[string]interface{}{
				"hint": "",
			},
		},
		"messageSignature": map[string]interface{}{
			"messageDigest": map[string]interface{}{
				"algorithm": "SHA2_256",
				"digest":    base64.StdEncoding.EncodeToString(hash[:]),
			},
			"signature": base64.StdEncoding.EncodeToString(sig),
		},
	}
	bundleBytes, err := json.Marshal(bundleMap)
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(td, "bundle.sigstore.json")
	if err := os.WriteFile(bundlePath, bundleBytes, 0644); err != nil {
		t.Fatal(err)
	}

	// 5. Invoke verifyBundle offline with the standard public key!
	vo := VerifyOpts{
		KeyRef:      pubKeyPath,
		BundlePath:  bundlePath,
		Offline:     true,
		IgnoreTlog:  true,
		IgnoreSCT:   true,
	}

	err = verifyBundle(t.Context(), vo, payloadPath, false)
	if err != nil {
		t.Fatalf("unexpected verification error: %v", err)
	}
}

func TestVerifyAttestationCmd(t *testing.T) {
	td := t.TempDir()

	// 1. Generate Key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes})
	pubKeyPath := filepath.Join(td, "key.pub")
	if err := os.WriteFile(pubKeyPath, pubPEM, 0644); err != nil {
		t.Fatal(err)
	}

	// 2. Construct mock in-toto statement wrapped in DSSE envelope
	statement := map[string]interface{}{
		"_type": "https://in-toto.io/Statement/v0.1",
		"subject": []interface{}{
			map[string]interface{}{
				"name": "test-payload",
				"digest": map[string]interface{}{
					"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				},
			},
		},
		"predicateType": "https://cosign.sigstore.dev/attestation/v0.1",
		"predicate":     map[string]interface{}{},
	}
	statementBytes, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	b64Statement := base64.StdEncoding.EncodeToString(statementBytes)

	envelope := map[string]interface{}{
		"payload":     b64Statement,
		"payloadType": "application/vnd.in-toto+json",
		"signatures": []interface{}{
			map[string]interface{}{
				"keyid": "",
				"sig":   "mock-signature-to-be-replaced",
			},
		},
	}
	
	// Standard DSSE signing signs the Pre-Authentication Encoding (PAE) bytes using securesystemslib/dsse
	pae := ssldsse.PAE("application/vnd.in-toto+json", statementBytes)
	
	hash := sha256.Sum256(pae)
	sig, err := ecdsa.SignASN1(rand.Reader, privKey, hash[:])
	if err != nil {
		t.Fatal(err)
	}

	envelope["signatures"] = []interface{}{
		map[string]interface{}{
			"keyid": "",
			"sig":   base64.StdEncoding.EncodeToString(sig),
		},
	}

	// 3. Construct standard Sigstore JSON bundle wrapping this DSSE envelope
	bundleMap := map[string]interface{}{
		"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"verificationMaterial": map[string]interface{}{
			"publicKey": map[string]interface{}{
				"hint": "",
			},
		},
		"dsseEnvelope": envelope,
	}
	bundleBytes, err := json.Marshal(bundleMap)
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(td, "bundle.sigstore.json")
	if err := os.WriteFile(bundlePath, bundleBytes, 0644); err != nil {
		t.Fatal(err)
	}

	// 4. Invoke verifyBundle for attestation offline
	vo := VerifyOpts{
		KeyRef:        pubKeyPath,
		BundlePath:    bundlePath,
		Offline:       true,
		IgnoreTlog:    true,
		IgnoreSCT:     true,
		PredicateType: "custom",
		CheckClaims:   false, // Bypasses local payload subject check for offline simplicity
	}

	err = verifyBundle(t.Context(), vo, "", true)
	if err != nil {
		t.Fatalf("unexpected attestation verification error: %v", err)
	}
}
