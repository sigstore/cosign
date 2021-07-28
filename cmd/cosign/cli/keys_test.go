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

package cli

import (
	"context"
	"crypto/rand"
	"io/ioutil"
	"testing"

	"github.com/sigstore/cosign/pkg/cosign"
)

func generateKeyFile(t *testing.T, tmpDir string, pf cosign.PassFunc) (privFile, pubFile string) {
	t.Helper()

	tmpPrivFile, err := ioutil.TempFile(tmpDir, "cosign_test_*.key")
	if err != nil {
		t.Fatalf("failed to create temp key file: %v", err)
	}
	defer tmpPrivFile.Close()
	tmpPubFile, err := ioutil.TempFile(tmpDir, "cosign_test_*.pub")
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
	}{
		{
			desc: "good password",

			writePw: pass("hello"),
			readPw:  pass("hello"),
		},
		{
			desc: "bad password",

			writePw:   pass("hello"),
			readPw:    pass("something else"),
			expectErr: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			testFile, _ := generateKeyFile(t, tmpDir, tc.writePw)

			signer, err := signerFromKeyRef(ctx, testFile, tc.readPw)
			if err != nil {
				if tc.expectErr {
					// Task failed successfully
					return
				}
				t.Fatalf("signerFromKeyRef returned error: %v", err)
			}
			if tc.expectErr {
				t.Fatalf("signerFromKeyRef should have returned error, got: %v", signer)
			}
		})
	}
}

func TestPublicKeyFromFileRef(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	ctx := context.Background()
	_, testFile := generateKeyFile(t, tmpDir, pass("whatever"))

	if _, err := publicKeyFromKeyRef(ctx, testFile); err != nil {
		t.Fatalf("publicKeyFromKeyRef returned error: %v", err)

	}
}

func TestLoadECDSAPrivateKey(t *testing.T) {
	// Generate a valid keypair
	keys, err := cosign.GenerateKeyPair(pass("hello"))
	if err != nil {
		t.Fatal(err)
	}

	// Load the private key with the right password
	if _, err := LoadECDSAPrivateKey(keys.PrivateBytes, []byte("hello")); err != nil {
		t.Errorf("unexpected error decrypting key: %s", err)
	}

	// Try it with the wrong one
	if _, err := LoadECDSAPrivateKey(keys.PrivateBytes, []byte("wrong")); err == nil {
		t.Error("expected error decrypting key!")
	}

	// Try to decrypt garbage
	buf := [100]byte{}
	if _, err := rand.Read(buf[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadECDSAPrivateKey(buf[:], []byte("wrong")); err == nil {
		t.Error("expected error decrypting key!")
	}
}
