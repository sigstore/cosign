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

package updatekeypair

import (
	"context"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/cosign/env"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func TestReadPasswordFn_newEnv(t *testing.T) {
	t.Setenv("COSIGN_NEW_PASSWORD", "newpassword")
	b, err := readPasswordFn(env.VariableNewPassword, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if diff := cmp.Diff("newpassword", string(b)); diff != "" {
		t.Fatal(diff)
	}
}

func TestReadPasswordFn_newEnvEmptyVal(t *testing.T) {
	t.Setenv("COSIGN_NEW_PASSWORD", "")
	b, err := readPasswordFn(env.VariableNewPassword, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(b) > 0 {
		t.Fatalf("expected empty string; got %q", string(b))
	}
}

func TestUpdateKeyPairCmd(t *testing.T) {
	td := t.TempDir()

	t.Setenv("COSIGN_PASSWORD", "initialpassword")
	t.Setenv("COSIGN_NEW_PASSWORD", "newpassword")

	keys, err := cosign.GenerateKeyPair(GetCurrentPass)
	if err != nil {
		t.Fatalf("generating key pair: %v", err)
	}

	keyFile := td + "/cosign.key"
	if err := os.WriteFile(keyFile, keys.PrivateBytes, 0600); err != nil {
		t.Fatalf("writing key file: %v", err)
	}

	// Run the update command.
	if err := UpdateKeyPairCmd(context.Background(), keyFile); err != nil {
		t.Fatalf("UpdateKeyPairCmd: %v", err)
	}

	// Verify the updated key can be loaded with the new password.
	updatedKeyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("reading updated key file: %v", err)
	}

	sv, err := cosign.LoadPrivateKey(updatedKeyBytes, []byte("newpassword"), nil)
	if err != nil {
		t.Fatalf("loading updated key with new password: %v", err)
	}

	// Verify the public key derived from the re-encrypted private key matches
	// the original public key — the underlying key material must be unchanged.
	pub, err := sv.PublicKey()
	if err != nil {
		t.Fatalf("getting public key from updated signer: %v", err)
	}
	updatedPubPEM, err := cryptoutils.MarshalPublicKeyToPEM(pub)
	if err != nil {
		t.Fatalf("marshalling updated public key: %v", err)
	}
	if diff := cmp.Diff(string(keys.PublicBytes), string(updatedPubPEM)); diff != "" {
		t.Fatalf("public key changed after password update (-want +got):\n%s", diff)
	}
}

func TestUpdateKeyPairCmd_WrongCurrentPassword(t *testing.T) {
	td := t.TempDir()

	t.Setenv("COSIGN_PASSWORD", "initialpassword")

	keys, err := cosign.GenerateKeyPair(GetCurrentPass)
	if err != nil {
		t.Fatalf("generating key pair: %v", err)
	}

	keyFile := td + "/cosign.key"
	if err := os.WriteFile(keyFile, keys.PrivateBytes, 0600); err != nil {
		t.Fatalf("writing key file: %v", err)
	}

	t.Setenv("COSIGN_PASSWORD", "wrongpassword")
	t.Setenv("COSIGN_NEW_PASSWORD", "newpassword")

	if err := UpdateKeyPairCmd(context.Background(), keyFile); err == nil {
		t.Fatal("expected error for wrong current password, but got none")
	}
}
