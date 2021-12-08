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
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/theupdateframework/go-tuf"
	"github.com/theupdateframework/go-tuf/client"
	tuf_leveldbstore "github.com/theupdateframework/go-tuf/client/leveldbstore"
)

// Only test the client without the remote fetch.

// Set up a temporary file system store
func generateTestRepo(t *testing.T, files map[string][]byte) (*fakeRemoteStore, tuf.LocalStore) {
	store := tuf.MemoryStore(nil, files)
	repo, err := tuf.NewRepo(store)
	if err := repo.Init(false); err != nil {
		t.Fatalf("unexpected error")
	}
	if err != nil {
		t.Fatalf("unexpected error")
	}
	for _, role := range []string{"root", "snapshot", "targets", "timestamp"} {
		_, err := repo.GenKey(role)
		if err != nil {
			t.Fatalf("unexpected error")
		}
	}
	for file := range files {
		repo.AddTarget(file, nil)
	}
	repo.Snapshot()
	repo.Timestamp()
	repo.Commit()

	meta, err := store.GetMeta()
	if err != nil {
		t.Fatalf("unexpected error")
	}
	remote := newFakeRemoteStore(meta, files)
	return remote, store
}

func newFakeFile(b []byte) *fakeFile {
	return &fakeFile{buf: bytes.NewReader(b), size: int64(len(b))}
}

type fakeFile struct {
	buf       *bytes.Reader
	bytesRead int
	size      int64
}

func (f *fakeFile) Read(p []byte) (int, error) {
	n, err := f.buf.Read(p)
	f.bytesRead += n
	return n, err
}

func (f *fakeFile) Close() error {
	f.buf.Seek(0, io.SeekStart)
	return nil
}

func newFakeRemoteStore(meta map[string]json.RawMessage, targets map[string][]byte) *fakeRemoteStore {
	remote := &fakeRemoteStore{meta: make(map[string]*fakeFile),
		targets: make(map[string]*fakeFile)}
	for name, data := range meta {
		remote.meta[name] = newFakeFile(data)
	}
	for name, data := range targets {
		remote.targets[name] = newFakeFile(data)
	}
	return remote
}

type fakeRemoteStore struct {
	meta    map[string]*fakeFile
	targets map[string]*fakeFile
}

func (f *fakeRemoteStore) GetMeta(name string) (io.ReadCloser, int64, error) {
	return f.get(name, f.meta)
}

func (f *fakeRemoteStore) GetTarget(path string) (io.ReadCloser, int64, error) {
	return f.get(path, f.targets)
}

func (f *fakeRemoteStore) get(name string, store map[string]*fakeFile) (io.ReadCloser, int64, error) {
	file, ok := store[name]
	if !ok {
		return nil, 0, client.ErrNotFound{File: name}
	}
	return file, file.size, nil
}

// Correct metadata, retrieve target
func TestValidMetadata(t *testing.T) {
	targetFiles := map[string][]byte{
		"foo.txt": []byte("foo")}
	remote, store := generateTestRepo(t, targetFiles)

	// Set up local with initial root.json
	tmp := t.TempDir()
	local, err := tuf_leveldbstore.FileLocalStore(tmp)
	if err != nil {
		t.Fatalf("unexpected error")
	}
	meta, _ := store.GetMeta()
	root := meta["root.json"]
	local.SetMeta("root.json", root)
	db := filepath.Join(tmp, "tuf.db")
	if err := os.Setenv(TufRootEnv, db); err != nil {
		t.Fatalf("error setting env")
	}
	defer os.Unsetenv(TufRootEnv)

	// Set up client
	rootClient := client.NewClient(local, remote)
	if err != nil {
		t.Fatalf("creating root client")
	}
	rootKeys, rootThreshold, err := getRootKeys(root)
	if err != nil {
		t.Fatalf("bad trusted root")
	}
	if err := rootClient.Init(rootKeys, rootThreshold); err != nil {
		t.Fatalf("initializing root client")
	}
	if err := updateMetadataAndDownloadTargets(rootClient); err != nil {
		t.Fatalf("updating from remote TUF repository")
	}

	target := "foo.txt"
	buf := ByteDestination{Buffer: &bytes.Buffer{}}
	err = getTargetHelper(target, &buf, rootClient)
	if err != nil {
		t.Fatalf("retrieving target %v", err)
	}
	if !bytes.Equal(buf.Bytes(), targetFiles[target]) {
		t.Fatalf("error retrieving target, expected %s got %s", buf.String(), targetFiles[target])
	}
}

func TestGetEmbeddedRoot(t *testing.T) {
	got, err := GetEmbeddedRoot()
	if err != nil {
		t.Fatalf("GetEmbeddedRoot() returned error: %v", err)
	}

	want, err := os.ReadFile(filepath.Join("repository", "root.json"))
	if err != nil {
		t.Fatalf("failed to read expected root from file: %v", err)
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("GetEmbeddedRoot() mismatch (-want +got):\n%s", diff)
	}
}
