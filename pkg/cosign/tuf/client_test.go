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

package tuf

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/theupdateframework/go-tuf"
	"github.com/theupdateframework/go-tuf/data"
	"github.com/theupdateframework/go-tuf/verify"
)

var targets = []string{
	"fulcio.crt.pem",
	"fulcio_v1.crt.pem",
	"ctfe.pub",
	"rekor.pub",
}

func TestNewFromEnv(t *testing.T) {
	td := t.TempDir()
	t.Setenv("TUF_ROOT", td)
	ctx := context.Background()

	// Make sure nothing is expired
	tuf, err := NewFromEnv(ctx)
	if err != nil {
		t.Fatal(err)
	}

	checkTargetsAndMeta(t, tuf)
	tuf.Close()

	// Now try with expired targets
	forceExpiration(t, true)
	tuf, err = NewFromEnv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tuf.Close()
	checkTargetsAndMeta(t, tuf)

	if err := Initialize(ctx, DefaultRemoteRoot, nil); err != nil {
		t.Error()
	}
	if l := dirLen(t, td); l == 0 {
		t.Errorf("expected filesystem writes, got %d entries", l)
	}

	// And go from there!
	tuf, err = NewFromEnv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	checkTargetsAndMeta(t, tuf)
	tuf.Close()
}

func TestNoCache(t *testing.T) {
	ctx := context.Background()
	// Once more with NO_CACHE
	t.Setenv("SIGSTORE_NO_CACHE", "true")
	td := t.TempDir()
	t.Setenv("TUF_ROOT", td)

	// Force expiration so we have some content to download
	forceExpiration(t, true)

	tuf, err := NewFromEnv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	checkTargetsAndMeta(t, tuf)
	tuf.Close()

	if l := dirLen(t, td); l != 0 {
		t.Errorf("expected no filesystem writes, got %d entries", l)
	}
}

func TestCache(t *testing.T) {
	ctx := context.Background()
	// Once more with NO_CACHE
	t.Setenv("SIGSTORE_NO_CACHE", "false")
	td := t.TempDir()
	t.Setenv("TUF_ROOT", td)

	// Make sure nothing is in that directory to start with
	if l := dirLen(t, td); l != 0 {
		t.Errorf("expected no filesystem writes, got %d entries", l)
	}

	// Nothing should get downloaded if everything is up to date
	forceExpiration(t, false)
	tuf, err := NewFromEnv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tuf.Close()

	if l := dirLen(t, td); l != 0 {
		t.Errorf("expected no filesystem writes, got %d entries", l)
	}

	// Force expiration so that content gets downloaded. This should write to disk
	forceExpiration(t, true)
	tuf, err = NewFromEnv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tuf.Close()

	if l := dirLen(t, td); l == 0 {
		t.Errorf("expected filesystem writes, got %d entries", l)
	}
	checkTargetsAndMeta(t, tuf)
}

func TestCustomRoot(t *testing.T) {
	ctx := context.Background()
	// Create a remote repository.
	td := t.TempDir()
	remote, r := newTufRepo(t, td, "foo")

	// Serve remote repository.
	s := httptest.NewServer(http.FileServer(http.Dir(filepath.Join(td, "repository"))))
	defer s.Close()

	// Initialize with custom root.
	tufRoot := t.TempDir()
	t.Setenv("TUF_ROOT", tufRoot)
	meta, err := remote.GetMeta()
	if err != nil {
		t.Error(err)
	}
	rootBytes, ok := meta["root.json"]
	if !ok {
		t.Error(err)
	}
	if err := Initialize(ctx, s.URL, rootBytes); err != nil {
		t.Error(err)
	}
	if l := dirLen(t, tufRoot); l == 0 {
		t.Errorf("expected filesystem writes, got %d entries", l)
	}

	// Successfully get target.
	tufObj, err := NewFromEnv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := tufObj.GetTarget("foo.txt"); err != nil || !bytes.Equal(b, []byte("foo")) {
		t.Fatal(err)
	}
	tufObj.Close()

	// Force expiration on the first timestamp and internal go-tuf verification.
	expCleanup := forceExpirationVersion(1, true)
	if _, err = NewFromEnv(ctx); err == nil {
		t.Errorf("expected expired timestamp from the remote")
	}
	expCleanup()

	// Update remote targets, issue a timestamp v2.
	updateTufRepo(t, td, r, "foo1")

	// Force expiration on the first timestamp.
	expCleanup = forceExpirationVersion(1, false)
	// Use newTuf and successfully get updated metadata using the cached remote location.
	tufObj, err = NewFromEnv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := tufObj.GetTarget("foo.txt"); err != nil || !bytes.Equal(b, []byte("foo1")) {
		t.Fatal(err)
	}
	expCleanup()
	tufObj.Close()
}

func checkTargetsAndMeta(t *testing.T, tuf *TUF) {
	// Check the targets
	t.Helper()
	for _, target := range targets {
		if _, err := tuf.GetTarget(target); err != nil {
			t.Fatal(err)
		}
	}

	// An invalid target
	if _, err := tuf.GetTarget("invalid"); err == nil {
		t.Error("expected error reading target, got nil")
	}

	// Check the TUF timestamp metadata
	if ts, err := tuf.GetTimestamp(); err != nil {
		t.Error("expected no error reading timestamp, got err")
	} else if len(ts) == 0 {
		t.Errorf("expected timestamp length of %d, got 0", len(ts))
	}
}

func dirLen(t *testing.T, td string) int {
	t.Helper()
	de, err := os.ReadDir(td)
	if err != nil {
		t.Fatal(err)
	}
	return len(de)
}

func forceExpiration(t *testing.T, expire bool) {
	oldIsExpiredTimestamp := isExpiredTimestamp
	isExpiredTimestamp = func(_ []byte) bool {
		return expire
	}
	t.Cleanup(func() {
		isExpiredTimestamp = oldIsExpiredTimestamp
	})
}

func forceExpirationVersion(version int, all bool) func() {
	oldIsExpiredTimestamp := isExpiredTimestamp
	oldIsExpired := verify.IsExpired
	isExpiredTimestamp = func(metadata []byte) bool {
		s := &data.Signed{}
		if err := json.Unmarshal(metadata, s); err != nil {
			return true
		}
		sm := &data.Timestamp{}
		if err := json.Unmarshal(s.Signed, sm); err != nil {
			return true
		}
		return sm.Version <= version
	}
	if all {
		verify.IsExpired = func(time time.Time) bool {
			return true
		}
	}
	return func() {
		isExpiredTimestamp = oldIsExpiredTimestamp
		verify.IsExpired = oldIsExpired
	}
}

func newTufRepo(t *testing.T, td string, targetData string) (tuf.LocalStore, *tuf.Repo) {
	remote := tuf.FileSystemStore(td, nil)
	r, err := tuf.NewRepo(remote)
	if err != nil {
		t.Error(err)
	}
	if err := r.Init(false); err != nil {
		t.Error(err)
	}
	for _, role := range []string{"root", "targets", "snapshot", "timestamp"} {
		if _, err := r.GenKey(role); err != nil {
			t.Error(err)
		}
	}
	targetPath := filepath.Join(td, "staged", "targets", "foo.txt")
	if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
		t.Error(err)
	}
	if err := ioutil.WriteFile(targetPath, []byte(targetData), 0600); err != nil {
		t.Error(err)
	}
	if err := r.AddTarget("foo.txt", nil); err != nil {
		t.Error(err)
	}
	if err := r.Snapshot(); err != nil {
		t.Error(err)
	}
	if err := r.Timestamp(); err != nil {
		t.Error(err)
	}
	if err := r.Commit(); err != nil {
		t.Error(err)
	}
	return remote, r
}

func updateTufRepo(t *testing.T, td string, r *tuf.Repo, targetData string) {
	targetPath := filepath.Join(td, "staged", "targets", "foo.txt")
	if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
		t.Error(err)
	}
	if err := ioutil.WriteFile(targetPath, []byte(targetData), 0600); err != nil {
		t.Error(err)
	}
	if err := r.AddTarget("foo.txt", nil); err != nil {
		t.Error(err)
	}
	if err := r.Snapshot(); err != nil {
		t.Error(err)
	}
	if err := r.Timestamp(); err != nil {
		t.Error(err)
	}
	if err := r.Commit(); err != nil {
		t.Error(err)
	}
}
