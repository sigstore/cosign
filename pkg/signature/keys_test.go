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

func pass(s string) cosign.PassFunc {
	return func(_ bool) ([]byte, error) {
		return []byte(s), nil
	}
}
