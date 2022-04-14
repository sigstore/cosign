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

package sign

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/sigstore/cosign/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/test"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/theupdateframework/go-tuf/encrypted"
)

func pass(s string) cosign.PassFunc {
	return func(_ bool) ([]byte, error) {
		return []byte(s), nil
	}
}

func generateCertificateFiles(t *testing.T, tmpDir string, pf cosign.PassFunc) (privFile, certFile, chainFile string, privKey *ecdsa.PrivateKey, cert *x509.Certificate, chain []*x509.Certificate) {
	t.Helper()

	rootCert, rootKey, _ := test.GenerateRootCa()
	subCert, subKey, _ := test.GenerateSubordinateCa(rootCert, rootKey)
	leafCert, privKey, _ := test.GenerateLeafCert("subject", "oidc-issuer", subCert, subKey)
	pemRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Raw})
	pemSub := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: subCert.Raw})
	pemLeaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Raw})

	x509Encoded, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		t.Fatalf("failed to encode private key: %v", err)
	}
	password := []byte{}
	if pf != nil {
		password, err = pf(true)
		if err != nil {
			t.Fatalf("failed to read password: %v", err)
		}
	}

	encBytes, err := encrypted.Encrypt(x509Encoded, password)
	if err != nil {
		t.Fatalf("failed to encrypt key: %v", err)
	}

	// store in PEM format
	privBytes := pem.EncodeToMemory(&pem.Block{
		Bytes: encBytes,
		Type:  cosign.CosignPrivateKeyPemType,
	})

	tmpPrivFile, err := os.CreateTemp(tmpDir, "cosign_test_*.key")
	if err != nil {
		t.Fatalf("failed to create temp key file: %v", err)
	}
	defer tmpPrivFile.Close()
	if _, err := tmpPrivFile.Write(privBytes); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	tmpCertFile, err := os.CreateTemp(tmpDir, "cosign.crt")
	if err != nil {
		t.Fatalf("failed to create temp certificate file: %v", err)
	}
	defer tmpCertFile.Close()
	if _, err := tmpCertFile.Write(pemLeaf); err != nil {
		t.Fatalf("failed to write certificate file: %v", err)
	}

	tmpChainFile, err := os.CreateTemp(tmpDir, "cosign_chain.crt")
	if err != nil {
		t.Fatalf("failed to create temp chain file: %v", err)
	}
	defer tmpChainFile.Close()
	pemChain := pemSub
	pemChain = append(pemChain, pemRoot...)
	if _, err := tmpChainFile.Write(pemChain); err != nil {
		t.Fatalf("failed to write chain file: %v", err)
	}

	return tmpPrivFile.Name(), tmpCertFile.Name(), tmpChainFile.Name(), privKey, leafCert, []*x509.Certificate{subCert, rootCert}
}

// TestSignCmdLocalKeyAndSk verifies the SignCmd returns an error
// if both a local key path and a sk are specified
func TestSignCmdLocalKeyAndSk(t *testing.T) {
	ro := &options.RootOptions{Timeout: options.DefaultTimeout}

	for _, ko := range []KeyOpts{
		// local and sk keys
		{
			KeyRef:   "testLocalPath",
			PassFunc: generate.GetPass,
			Sk:       true,
		},
	} {
		err := SignCmd(ro, ko, options.RegistryOptions{}, nil, nil, "", "", false, "", "", "", false, false, "")
		if (errors.Is(err, &options.KeyParseError{}) == false) {
			t.Fatal("expected KeyParseError")
		}
	}
}

func Test_signerFromKeyRefSuccess(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()
	keyFile, certFile, chainFile, privKey, cert, chain := generateCertificateFiles(t, tmpDir, pass("foo"))

	signer, err := signerFromKeyRef(ctx, certFile, chainFile, keyFile, pass("foo"))
	if err != nil {
		t.Fatalf("unexpected error generating signer: %v", err)
	}
	// Expect public key matches
	pubKey, err := signer.SignerVerifier.PublicKey()
	if err != nil {
		t.Fatalf("unexpected error fetching pubkey: %v", err)
	}
	if !privKey.Public().(*ecdsa.PublicKey).Equal(pubKey) {
		t.Fatalf("public keys must be equal")
	}
	// Expect certificate matches
	expectedPemBytes, err := cryptoutils.MarshalCertificateToPEM(cert)
	if err != nil {
		t.Fatalf("unexpected error marshalling certificate: %v", err)
	}
	if !reflect.DeepEqual([]byte(signer.Cert), expectedPemBytes) {
		t.Fatalf("certificates must match")
	}
	// Expect certificate chain matches
	expectedPemBytesChain, err := cryptoutils.MarshalCertificatesToPEM(chain)
	if err != nil {
		t.Fatalf("unexpected error marshalling certificate chain: %v", err)
	}
	if !reflect.DeepEqual([]byte(strings.Join(signer.Chain, "\n")), expectedPemBytesChain) {
		t.Fatalf("certificate chains must match")
	}
}

func Test_signerFromKeyRefFailure(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()
	keyFile, certFile, _, _, _, _ := generateCertificateFiles(t, tmpDir, pass("foo"))
	// Second set of files
	tmpDir2 := t.TempDir()
	_, certFile2, chainFile2, _, _, _ := generateCertificateFiles(t, tmpDir2, pass("bar"))

	// Public keys don't match
	_, err := signerFromKeyRef(ctx, certFile2, chainFile2, keyFile, pass("foo"))
	if err == nil || err.Error() != "public key in certificate does not match the provided public key" {
		t.Fatalf("expected mismatched keys error, got %v", err)
	}
	// Certificate chain cannot be verified
	_, err = signerFromKeyRef(ctx, certFile, chainFile2, keyFile, pass("foo"))
	if err == nil || !strings.Contains(err.Error(), "unable to validate certificate chain") {
		t.Fatalf("expected chain verification error, got %v", err)
	}
	// Certificate chain specified without certificate
	_, err = signerFromKeyRef(ctx, "", chainFile2, keyFile, pass("foo"))
	if err == nil || !strings.Contains(err.Error(), "no leaf certificate found or provided while specifying chain") {
		t.Fatalf("expected no leaf error, got %v", err)
	}
}

func Test_signerFromKeyRefFailureEmptyChainFile(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()
	keyFile, certFile, _, _, _, _ := generateCertificateFiles(t, tmpDir, pass("foo"))

	tmpChainFile, err := os.CreateTemp(tmpDir, "cosign_chain_empty.crt")
	if err != nil {
		t.Fatalf("failed to create temp chain file: %v", err)
	}
	defer tmpChainFile.Close()
	if _, err := tmpChainFile.Write([]byte{}); err != nil {
		t.Fatalf("failed to write chain file: %v", err)
	}

	_, err = signerFromKeyRef(ctx, certFile, tmpChainFile.Name(), keyFile, pass("foo"))
	if err == nil || err.Error() != "no certificates in certificate chain" {
		t.Fatalf("expected empty chain error, got %v", err)
	}
}
