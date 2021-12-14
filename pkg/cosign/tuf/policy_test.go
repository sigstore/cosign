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

// Contains root policy definitions.
// Eventually, this will move this to go-tuf definitions.

package tuf

import (
	"encoding/json"
	"testing"
)

func TestAddKey(t *testing.T) {
	root := NewRoot()
	publicKey := FulcioVerificationKey("test@rekor.dev", "")
	if !root.AddKey(publicKey) {
		t.Errorf("Adding new key failed")
	}
	if _, ok := root.Keys[publicKey.ID()]; !ok {
		t.Errorf("Error adding public key")
	}
	// Add duplicate key.
	if root.AddKey(publicKey) {
		t.Errorf("Duplicate key should not add to dictionary")
	}
	if len(root.Keys) != 1 {
		t.Errorf("Root keys should contain exactly one key.")
	}
}

func TestValidKey(t *testing.T) {
	root := NewRoot()
	publicKey := FulcioVerificationKey("test@rekor.dev", "https://accounts.google.com")
	if !root.AddKey(publicKey) {
		t.Errorf("Adding new key failed")
	}
	role := &Role{KeyIDs: []string{}, Threshold: 1}
	role.AddKeysWithThreshold([]*Key{publicKey}, 2)
	root.Roles["root"] = role

	if _, ok := root.Keys[publicKey.ID()]; !ok {
		t.Errorf("Error adding public key")
	}
	if _, err := root.ValidKey(publicKey, "root"); err != nil {
		t.Errorf("Error checking key validit %s", err)
	}
	// Now change issuer, and expect error.
	publicKey = FulcioVerificationKey("test@rekor.dev", "")
	if _, err := root.ValidKey(publicKey, "root"); err == nil {
		t.Errorf("Expected invalid key with mismatching issuer")
	}
}

func TestRootRole(t *testing.T) {
	root := NewRoot()
	publicKey := FulcioVerificationKey("test@rekor.dev", "")
	role := &Role{KeyIDs: []string{}, Threshold: 1}
	role.AddKeysWithThreshold([]*Key{publicKey}, 2)
	root.Roles["root"] = role
	policy, err := root.Marshal()
	if err != nil {
		t.Errorf("Error marshalling root policy")
	}
	newRoot := Root{}
	if err := json.Unmarshal(policy.Policy, &newRoot); err != nil {
		t.Errorf("Error marshalling root policy")
	}
	rootRole, ok := newRoot.Roles["root"]
	if !ok {
		t.Errorf("Missing root role")
	}
	if len(rootRole.KeyIDs) != 1 {
		t.Errorf("Missing root key ID")
	}
	if rootRole.KeyIDs[0] != publicKey.ID() {
		t.Errorf("Bad root role key ID")
	}
	if rootRole.Threshold != 2 {
		t.Errorf("Threshold incorrect")
	}
}
