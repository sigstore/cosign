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
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/secure-systems-lab/go-securesystemslib/encrypted"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/internal/test"
	"github.com/sigstore/cosign/v3/pkg/cosign"
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
	_, err := SignBlobCmd(t.Context(), rootOpts, keyOpts, blobPath, "", "", true, "", "", false)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}

	// Test file outputs
	keyOpts.NewBundleFormat = true
	sigPath := filepath.Join(td, "output.sig")
	certPath := filepath.Join(td, "output.pem")
	_, err = SignBlobCmd(t.Context(), rootOpts, keyOpts, blobPath, "", "", false, sigPath, certPath, false)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}

	// Test signing with a certificate
	rootCert, rootKey, _ := test.GenerateRootCa()
	cert, certPrivKey, _ := test.GenerateLeafCert("subject@mail.com", "oidc-issuer", rootCert, rootKey)
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

	_, err = SignBlobCmd(t.Context(), rootOpts, keyOpts, blobPath, signCertPath, "", false, "", "", false)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
}

func TestSignBlobCmdWithCertificateChain(t *testing.T) {
	td := t.TempDir()
	bundlePath := filepath.Join(td, "bundle.sigstore.json")

	// Generate Certificate Chain (Root CA -> Intermediate CA -> Leaf Certificate)
	rootCertificateAuthority, rootKey, err := test.GenerateRootCa()
	if err != nil {
		t.Fatalf("failed to generate root CA: %v", err)
	}

	intermediateCertificateAuthority, intermediateKey, err := test.GenerateSubordinateCa(rootCertificateAuthority, rootKey)
	if err != nil {
		t.Fatalf("failed to generate intermediate CA: %v", err)
	}

	leafCertificate, leafPrivateKey, err := test.GenerateLeafCert("subject@mail.com", "oidc-issuer", intermediateCertificateAuthority, intermediateKey)
	if err != nil {
		t.Fatalf("failed to generate leaf cert: %v", err)
	}

	// Create Full Certificate Chain (.pem)
	var certificateChainPem []byte
	certificateChainPem = append(certificateChainPem, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCertificate.Raw})...)
	certificateChainPem = append(certificateChainPem, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediateCertificateAuthority.Raw})...)
	certificateChainPem = append(certificateChainPem, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCertificateAuthority.Raw})...)
	certificateChainPath := writeFile(t, td, string(certificateChainPem), "chain.pem")

	// Encode Private Key (.pem)
	x509Encoded, err := x509.MarshalPKCS8PrivateKey(leafPrivateKey)
	if err != nil {
		t.Fatalf("unexpected error marshaling private key: %v", err)
	}

	encryptedPrivateKey, err := encrypted.Encrypt(x509Encoded, nil)
	if err != nil {
		t.Fatalf("unexpected error encrypting private key: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Bytes: encryptedPrivateKey,
		Type:  cosign.SigstorePrivateKeyPemType,
	})

	privateKeyReference := writeFile(t, td, string(pemBytes), "certkey.pem")

	blob := []byte("foo")
	blobPath := writeFile(t, td, string(blob), "foo.txt")

	rootOpts := &options.RootOptions{}
	keyOpts := options.KeyOpts{
		KeyRef:          privateKeyReference,
		BundlePath:      bundlePath,
		NewBundleFormat: true,
	}

	_, err = SignBlobCmd(t.Context(), rootOpts, keyOpts, blobPath, certificateChainPath, "", false, "", "", false)
	if err != nil {
		t.Fatalf("unexpected error signing with certificate chain: %v", err)
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
