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
	"bytes"
	"context"
	"crypto"
	"errors"
	"os"
	"testing"

	"github.com/sigstore/cosign/v2/pkg/blob"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

const ed25519PrivateKey = `-----BEGIN ENCRYPTED SIGSTORE PRIVATE KEY-----
eyJrZGYiOnsibmFtZSI6InNjcnlwdCIsInBhcmFtcyI6eyJOIjo2NTUzNiwiciI6
OCwicCI6MX0sInNhbHQiOiJxYVVSY1ppbTN3RE9ZMVlselFGaFdVWHBnMU5tZlAv
YndiM2ZpWE54ck5BPSJ9LCJjaXBoZXIiOnsibmFtZSI6Im5hY2wvc2VjcmV0Ym94
Iiwibm9uY2UiOiJMRjNVN3crNXgzWmRvMlNGUkFicE1nY1N5Y2sxN3R1LyJ9LCJj
aXBoZXJ0ZXh0IjoiY2lUQTYrODVWRDdsTlpwRTVLdmpMdjJrTXNZdmtvOHNHV0tq
QTRYZDY2WFRaTUw3UG5xczQ2NloycDRyWGJUdXBlcStwSXlnSXhvS29UVmFHbG9N
RXc9PSJ9
-----END ENCRYPTED SIGSTORE PRIVATE KEY-----
`

const ed25519PublicKey = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAFs2AhZmYWkoEsqUf6yotyIwVb5uATpuKK194tq8OkoQ=
-----END PUBLIC KEY-----
`

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
			tc := tc
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
	kms.AddProvider("errorkms://", func(_ context.Context, _ string, _ crypto.Hash, _ ...signature.RPCOption) (kms.SignerVerifier, error) {
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

func TestPublicKeyFromKeyRefWithOpts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tmpDir := t.TempDir()

	// Create a temporary public key file
	tmpPubFile, err := os.CreateTemp(tmpDir, "cosign_test_*.pub")
	if err != nil {
		t.Fatalf("failed to create temp pub file: %v", err)
	}
	t.Cleanup(func() {
		tmpPubFile.Close()
	})

	if _, err := tmpPubFile.Write([]byte(ed25519PublicKey)); err != nil {
		t.Fatalf("failed to write pub file: %v", err)
	}

	// Test data to sign and verify
	testData := []byte("test data")

	testCases := []struct {
		name         string
		signerOpts   []signature.LoadOption
		verifierOpts []signature.LoadOption
		expectErr    bool
	}{
		{
			name:         "pure ed25519 signer/verifier",
			signerOpts:   []signature.LoadOption{},
			verifierOpts: []signature.LoadOption{},
			expectErr:    false,
		},
		{
			name:         "ed25519ph signer/verifier",
			signerOpts:   []signature.LoadOption{options.WithED25519ph()},
			verifierOpts: []signature.LoadOption{options.WithED25519ph()},
			expectErr:    false,
		},
		{
			name:         "ed25519 pure signer/ed25519ph verifier",
			signerOpts:   []signature.LoadOption{},
			verifierOpts: []signature.LoadOption{options.WithED25519ph()},
			expectErr:    true,
		},
		{
			name:         "ed25519ph signer/ed25519 verifier",
			signerOpts:   []signature.LoadOption{options.WithED25519ph()},
			verifierOpts: []signature.LoadOption{},
			expectErr:    true,
		},
	}

	os.Setenv("MY_ENV_VAR", string(ed25519PrivateKey))
	t.Cleanup(func() {
		os.Unsetenv("MY_ENV_VAR")
	})

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			verifier, err := PublicKeyFromKeyRefWithOpts(ctx, tmpPubFile.Name(), tc.verifierOpts...)
			if err != nil {
				t.Fatalf("failed to load public key: %v", err)
			}

			signerStandard, err := SignerVerifierFromKeyRefWithOpts(ctx, "env://MY_ENV_VAR", pass(""), tc.signerOpts...)
			if err != nil {
				t.Fatalf("failed to load standard signer: %v", err)
			}
			sig, err := signerStandard.SignMessage(bytes.NewReader(testData), options.WithContext(ctx))
			if err != nil {
				t.Fatalf("failed to sign message: %v", err)
			}

			err = verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(testData), options.WithContext(ctx))
			if tc.expectErr && err == nil {
				t.Fatalf("expected verification error, got none")
			} else if !tc.expectErr && err != nil {
				t.Fatalf("unexpected verification error: %v", err)
			}
		})
	}
}
