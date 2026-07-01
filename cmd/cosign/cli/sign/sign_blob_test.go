// Copyright 2024 The Sigstore Authors.
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

package sign

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/secure-systems-lab/go-securesystemslib/encrypted"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/signcommon"
	"github.com/sigstore/cosign/v3/internal/test"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/sigstore-go/pkg/root"
)

func TestSignBlobCmd(t *testing.T) {
	td := t.TempDir()
	bundlePath := filepath.Join(td, "bundle.sigstore.json")

	keys, _ := cosign.GenerateKeyPair(nil)
	keyRef := writeFile(t, td, string(keys.PrivateBytes), "key.pem")

	blob := []byte("foo")
	blobPath := writeFile(t, td, string(blob), "foo.txt")

	rootOpts := &options.RootOptions{}
	keyOpts := options.KeyOpts{KeyRef: keyRef, BundlePath: bundlePath}

	// Test happy path
	if err := SignBlobCmd(t.Context(), rootOpts, keyOpts, blobPath, "", ""); err != nil {
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

	if err := SignBlobCmd(t.Context(), rootOpts, keyOpts, blobPath, signCertPath, ""); err != nil {
		t.Fatalf("unexpected error %v", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x509Encoded, err = x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	encBytes, err = encrypted.Encrypt(x509Encoded, nil)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes = pem.EncodeToMemory(&pem.Block{
		Bytes: encBytes,
		Type:  cosign.SigstorePrivateKeyPemType,
	})

	// Test signing using Ed25519 key with custom signing config and no transparency log upload
	edKeyRef := writeFile(t, td, string(pemBytes), "ed_key.pem")
	keyOpts = options.KeyOpts{KeyRef: edKeyRef, BundlePath: bundlePath}
	keyOpts.SigningConfig = signcommon.NewEmptySigningConfig()
	sc, err := root.NewSigningConfig(
		root.SigningConfigMediaType02,
		nil,
		nil,
		nil,
		root.ServiceConfiguration{},
		nil,
		root.ServiceConfiguration{},
	)
	if err != nil {
		t.Fatal(err)
	}
	keyOpts.SigningConfig = sc
	if err := SignBlobCmd(t.Context(), rootOpts, keyOpts, blobPath, "", ""); err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	var b1 struct {
		MessageSignature struct {
			Signature string `json:"signature"`
		} `json:"messageSignature"`
	}
	bytes1, _ := os.ReadFile(bundlePath)
	json.Unmarshal(bytes1, &b1)
	decodedSig, _ := base64.StdEncoding.DecodeString(b1.MessageSignature.Signature)
	if !ed25519.Verify(pub, blob, decodedSig) {
		errString := "expected ed25519 signature"
		if ed25519.VerifyWithOptions(pub, blob, decodedSig, &ed25519.Options{Hash: crypto.SHA512}) == nil {
			errString += ", received ed25519ph signature"
		}
		t.Fatal("signature verification failed: " + errString)
	}

	// Test signing using Ed25519 key with default signing config and no transparency log upload
	keyOpts = options.KeyOpts{KeyRef: edKeyRef, BundlePath: bundlePath}
	if err := SignBlobCmd(t.Context(), rootOpts, keyOpts, blobPath, "", ""); err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	var b2 struct {
		MessageSignature struct {
			Signature string `json:"signature"`
		} `json:"messageSignature"`
	}
	bytes2, _ := os.ReadFile(bundlePath)
	json.Unmarshal(bytes2, &b2)
	decodedSig, _ = base64.StdEncoding.DecodeString(b2.MessageSignature.Signature)
	if !ed25519.Verify(pub, blob, decodedSig) {
		errString := "expected ed25519 signature"
		if ed25519.VerifyWithOptions(pub, blob, decodedSig, &ed25519.Options{Hash: crypto.SHA512}) == nil {
			errString += ", received ed25519ph signature"
		}
		t.Fatal("signature verification failed: " + errString)
	}
}

func writeFile(t *testing.T, td string, blob string, name string) string {
	// Write blob to disk
	blobPath := filepath.Join(td, name)
	if err := os.WriteFile(blobPath, []byte(blob), 0o644); err != nil {
		t.Fatal(err)
	}
	return blobPath
}
