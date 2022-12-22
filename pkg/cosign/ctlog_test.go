// Copyright 2022 The Sigstore Authors.
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

package cosign

import (
	"context"
	"os"
	"testing"
)

const (
	ctlogPublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7D2WvgqSzs9jpdJsOJ5Nl6xg8JXm
Nmo7M3bN7+dQddw9Ibc2R3SV8tzBZw0rST8FKcn4apJepcKM4qUpYUeNfw==
-----END PUBLIC KEY-----
`
	// This is the LogID constructed from above public key.
	ctLogID = "0bac0fddd0c15fbc46f8b1bf51c2b57676a9f262294fe13417d85602e73f392a"
)

func TestGetCTLogPubKeys(t *testing.T) {
	keys, err := GetCTLogPubs(context.Background())
	if err != nil {
		t.Errorf("Unexpected error calling GetCTLogPubs, expected nil: %v", err)
	}
	if len(keys.Keys) == 0 {
		t.Errorf("expected 1 or more keys, got 0")
	}
	// check that the mapping of key digest to key is correct
	for logID, key := range keys.Keys {
		expectedLogID, err := GetTransparencyLogID(key.PubKey)
		if err != nil {
			t.Fatalf("unexpected error generated log ID: %v", err)
		}
		if logID != expectedLogID {
			t.Fatalf("key digests are not equal")
		}
	}
}

func TestGetCTLogPubKeysAlt(t *testing.T) {
	pkFile, err := os.CreateTemp(t.TempDir(), "cosign_verify_sct_*.key")
	if err != nil {
		t.Fatalf("failed to create temp public key file: %v", err)
	}
	defer pkFile.Close()
	if _, err := pkFile.Write([]byte(ctlogPublicKey)); err != nil {
		t.Fatalf("failed to write public key file: %v", err)
	}
	t.Setenv("SIGSTORE_CT_LOG_PUBLIC_KEY_FILE", pkFile.Name())

	keys, err := GetCTLogPubs(context.Background())
	if err != nil {
		t.Errorf("Unexpected error calling GetCTLogPubs, expected nil: %v", err)
	}
	if len(keys.Keys) == 0 {
		t.Errorf("expected 1 or more keys, got 0")
	}
	// check that the mapping of key digest to key is correct
	for logID, key := range keys.Keys {
		expectedLogID, err := GetTransparencyLogID(key.PubKey)
		if err != nil {
			t.Fatalf("unexpected error generated log ID: %v", err)
		}
		if logID != expectedLogID {
			t.Fatalf("key digests are not equal")
		}
		if expectedLogID != ctLogID {
			t.Fatalf("key digest computed is different from expected, got: %s want: %s", logID, ctLogID)
		}
	}
}
