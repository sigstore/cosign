//
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

package tuf

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/theupdateframework/go-tuf"
	"github.com/theupdateframework/go-tuf/data"
	"github.com/theupdateframework/go-tuf/pkg/keys"
)

func addDelegation(t *testing.T, td string, remote tuf.LocalStore, r *tuf.Repo, delegation, path string, threshold int) {
	delegatedKey, err := keys.GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.SaveSigner(delegation, delegatedKey); err != nil {
		t.Fatal(err)
	}
	delegatee := data.DelegatedRole{
		Name:        delegation,
		KeyIDs:      delegatedKey.PublicData().IDs(),
		Paths:       []string{path},
		Terminating: true,
		Threshold:   threshold,
	}
	publicKeys := []*data.PublicKey{}
	publicKeys = append(publicKeys, delegatedKey.PublicData())

	if err := r.AddTargetsDelegation("targets", delegatee, publicKeys); err != nil {
		t.Fatal(err)
	}
	if err := r.Snapshot(); err != nil {
		t.Fatal(err)
	}
	if err := r.Timestamp(); err != nil {
		t.Fatal(err)
	}
	if err := r.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestFetchDelegations(t *testing.T) {
	ctx := context.Background()
	// Create a remote repository with delegations.
	td := t.TempDir()
	remote, r := newTufRepo(t, td, "foo")
	delegationThreshold := 1
	delegateName := "repokitty"
	delegatedPath := "gcr.io/repokitty/**"
	addDelegation(t, td, remote, r, delegateName, delegatedPath, delegationThreshold)

	// Serve remote repository.
	s := httptest.NewServer(http.FileServer(http.Dir(filepath.Join(td, "repository"))))
	defer s.Close()

	// Initialize with custom root.
	tufRoot := t.TempDir()
	t.Setenv("TUF_ROOT", tufRoot)
	meta, err := remote.GetMeta()
	if err != nil {
		t.Fatal(err)
	}
	rootBytes, ok := meta["root.json"]
	if !ok {
		t.Fatal(err)
	}
	if err := Initialize(ctx, s.URL, rootBytes); err != nil {
		t.Fatal(err)
	}
	if l := dirLen(t, tufRoot); l == 0 {
		t.Errorf("expected filesystem writes, got %d entries", l)
	}

	// Get delegations by name and path.
	tufObj, err := NewFromEnv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	d, err := tufObj.GetDelegationByPath("gcr.io/repokitty/cat")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(d.Delegatee.Name, delegateName) {
		t.Errorf("expected delegatee %s, got %s", delegateName, d.Delegatee.Name)
	}
	// check delegation threshold
	if d.Delegatee.Threshold != delegationThreshold {
		t.Fatal(err)
	}
	// extract key verifiers for this delegation
	for _, expectedKey := range d.Delegatee.KeyIDs {
		verifier, err := d.DB.GetVerifier(expectedKey)
		if err != nil {
			t.Fatal(err)
		}
		// match this verifier against the added key
		verifier.Public()
	}

	tufObj.Close()
}
