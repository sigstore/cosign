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

package signature

import (
	"context"
	"crypto"
	"crypto/x509/pkix"
	"errors"
	"net"
	"net/url"
	"os"
	"testing"

	"github.com/sigstore/cosign/pkg/blob"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/test"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	sigsignature "github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms"
)

func generateKeyFile(t *testing.T, tmpDir string, pf cosign.PassFunc) (privFile, pubFile string) {
	t.Helper()

	tmpPrivFile, err := os.CreateTemp(tmpDir, "cosign_test_*.key")
	if err != nil {
		t.Fatalf("failed to create temp key file: %v", err)
	}
	defer tmpPrivFile.Close()
	tmpPubFile, err := os.CreateTemp(tmpDir, "cosign_test_*.pub")
	if err != nil {
		t.Fatalf("failed to create temp pub file: %v", err)
	}
	defer tmpPubFile.Close()

	// Generate a valid keypair.
	keys, err := cosign.GenerateKeyPair(pf)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	if _, err := tmpPrivFile.Write(keys.PrivateBytes); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}
	if _, err := tmpPubFile.Write(keys.PublicBytes); err != nil {
		t.Fatalf("failed to write pub file: %v", err)
	}
	return tmpPrivFile.Name(), tmpPubFile.Name()
}

func TestSignerFromPrivateKeyFileRef(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	ctx := context.Background()

	testCases := []struct {
		desc string

		writePw   cosign.PassFunc
		readPw    cosign.PassFunc
		expectErr bool
	}{{
		desc: "good password",

		writePw: pass("hello"),
		readPw:  pass("hello"),
	}, {
		desc: "bad password",

		writePw:   pass("hello"),
		readPw:    pass("something else"),
		expectErr: true,
	}}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()
			testFile, _ := generateKeyFile(t, tmpDir, tc.writePw)

			signer, err := SignerFromKeyRef(ctx, testFile, tc.readPw)
			if err != nil {
				if tc.expectErr {
					// Task failed successfully
					return
				}
				t.Fatalf("SignerFromKeyRef returned error: %v", err)
			}
			if tc.expectErr {
				t.Fatalf("SignerFromKeyRef should have returned error, got: %v", signer)
			}
		})
	}
}

func TestPublicKeyFromFileRef(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	ctx := context.Background()
	_, testFile := generateKeyFile(t, tmpDir, pass("whatever"))

	if _, err := PublicKeyFromKeyRef(ctx, testFile); err != nil {
		t.Fatalf("PublicKeyFromKeyRef returned error: %v", err)
	}
}

func TestPublicKeyFromEnvVar(t *testing.T) {
	keys, err := cosign.GenerateKeyPair(pass("whatever"))
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}
	ctx := context.Background()

	os.Setenv("MY_ENV_VAR", string(keys.PublicBytes))
	defer os.Unsetenv("MY_ENV_VAR")
	if _, err := PublicKeyFromKeyRef(ctx, "env://MY_ENV_VAR"); err != nil {
		t.Fatalf("PublicKeyFromKeyRef returned error: %v", err)
	}
}

func TestSignerVerifierFromEnvVar(t *testing.T) {
	passFunc := pass("whatever")
	keys, err := cosign.GenerateKeyPair(passFunc)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}
	ctx := context.Background()

	os.Setenv("MY_ENV_VAR", string(keys.PrivateBytes))
	defer os.Unsetenv("MY_ENV_VAR")
	if _, err := SignerVerifierFromKeyRef(ctx, "env://MY_ENV_VAR", passFunc); err != nil {
		t.Fatalf("SignerVerifierFromKeyRef returned error: %v", err)
	}
}

func TestVerifierForKeyRefError(t *testing.T) {
	kms.AddProvider("errorkms://", func(ctx context.Context, _ string, hf crypto.Hash, _ ...sigsignature.RPCOption) (kms.SignerVerifier, error) {
		return nil, errors.New("bad")
	})
	var uerr *blob.UnrecognizedSchemeError

	ctx := context.Background()
	_, err := PublicKeyFromKeyRef(ctx, "errorkms://bad")
	if err == nil {
		t.Fatalf("PublicKeyFromKeyRef didn't return any error")
	} else if errors.As(err, &uerr) {
		t.Fatalf("PublicKeyFromKeyRef returned UnrecognizedSchemeError: %v", err)
	}

	_, err = PublicKeyFromKeyRef(ctx, "badscheme://bad")
	if err == nil {
		t.Fatalf("PublicKeyFromKeyRef didn't return any error")
	} else if !errors.As(err, &uerr) {
		t.Fatalf("PublicKeyFromKeyRef didn't return UnrecognizedSchemeError: %v", err)
	}
}

func pass(s string) cosign.PassFunc {
	return func(_ bool) ([]byte, error) {
		return []byte(s), nil
	}
}

func TestCertSubject(t *testing.T) {
	rootCert, rootKey, _ := test.GenerateRootCa()
	subCert, subKey, _ := test.GenerateSubordinateCa(rootCert, rootKey)

	// generate with OtherName, which will override other SANs
	ext, err := cryptoutils.MarshalOtherNameSAN("subject-othername", true)
	if err != nil {
		t.Fatalf("error marshalling SANs: %v", err)
	}
	exts := []pkix.Extension{*ext}
	leafCert, _, _ := test.GenerateLeafCert("unused", "oidc-issuer", subCert, subKey, exts...)
	if otherName := CertSubject(leafCert); otherName != "subject-othername" {
		t.Fatalf("unexpected otherName, got %s", otherName)
	}

	// generate with email
	leafCert, _, _ = test.GenerateLeafCert("subject-email", "oidc-issuer", subCert, subKey)
	if email := CertSubject(leafCert); email != "subject-email" {
		t.Fatalf("unexpected email address, got %s", email)
	}

	// generate with URI
	uri, _ := url.Parse("spiffe://domain/user")
	leafCert, _, _ = test.GenerateLeafCertWithSubjectAlternateNames([]string{}, []string{}, []net.IP{}, []*url.URL{uri}, "oidc-issuer", subCert, subKey)
	if uri := CertSubject(leafCert); uri != "spiffe://domain/user" {
		t.Fatalf("unexpected URI, got %s", uri)
	}
}
