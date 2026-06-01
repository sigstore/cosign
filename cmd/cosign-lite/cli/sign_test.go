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
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/encrypted"
	"github.com/sigstore/cosign/v3/internal/test"
	"github.com/sigstore/cosign/v3/pkg/cosign"
)

func TestSignCmd(t *testing.T) {
	td := t.TempDir()
	bundlePath := filepath.Join(td, "bundle.sigstore.json")

	keys, _ := cosign.GenerateKeyPair(nil)
	keyRef := writeFile(t, td, string(keys.PrivateBytes), "key.pem")

	blob := []byte("foo")
	blobPath := writeFile(t, td, string(blob), "foo.txt")

	rootOpts := &RootOptions{
		Timeout: 3 * time.Minute,
	}
	keyOpts := KeyOpts{
		KeyRef:           keyRef,
		BundlePath:       bundlePath,
		SkipConfirmation: true,
	}

	// Test happy path
	err := signBundle(t.Context(), rootOpts, keyOpts, blobPath, "", "", false, false)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}

	// Test signing with a certificate
	rootCert, rootKey, _ := test.GenerateRootCa()
	cert, certPrivKey, _ := test.GenerateLeafCert("subject", "oidc-issuer", rootCert, rootKey)
	certPemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	signCertPath := writeFile(t, td, string(certPemBytes), "cert.pem")
	x509Encoded, err := x509.MarshalPKCS8PrivateKey(certPrivKey)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	encBytes, err := encrypted.Encrypt(x509Encoded, nil)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Bytes: encBytes,
		Type:  cosign.SigstorePrivateKeyPemType,
	})
	certPrivKeyRef := writeFile(t, td, string(pemBytes), "certkey.pem")
	keyOpts.KeyRef = certPrivKeyRef

	err = signBundle(t.Context(), rootOpts, keyOpts, blobPath, signCertPath, "", false, false)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
}

func TestAttestCmd(t *testing.T) {
	td := t.TempDir()
	bundlePath := filepath.Join(td, "bundle.sigstore.json")

	keys, _ := cosign.GenerateKeyPair(nil)
	keyRef := writeFile(t, td, string(keys.PrivateBytes), "key.pem")

	statement := []byte(`{"_type":"https://in-toto.io/Statement/v0.1","subject":[{"name":"foo","digest":{"sha256":"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"}}],"predicateType":"cosign.sigstore.dev/attestation/v1","predicate":{}}`)
	statementPath := writeFile(t, td, string(statement), "statement.json")

	rootOpts := &RootOptions{
		Timeout: 3 * time.Minute,
	}
	keyOpts := KeyOpts{
		KeyRef:           keyRef,
		BundlePath:       bundlePath,
		SkipConfirmation: true,
	}

	err := signBundle(t.Context(), rootOpts, keyOpts, statementPath, "", "", false, true)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}

	bundleBytes, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("reading bundle file: %v", err)
	}

	if !strings.Contains(string(bundleBytes), "dsseEnvelope") {
		t.Errorf("expected bundle to contain dsseEnvelope, got %s", string(bundleBytes))
	}
}

func writeFile(t *testing.T, td string, blob string, name string) string {
	blobPath := filepath.Join(td, name)
	if err := os.WriteFile(blobPath, []byte(blob), 0o644); err != nil {
		t.Fatal(err)
	}
	return blobPath
}
