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
	"embed"
	"encoding/json"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"github.com/pkg/errors"
	gtuf "github.com/theupdateframework/go-tuf"
	"github.com/theupdateframework/go-tuf/client"
	tuf_leveldbstore "github.com/theupdateframework/go-tuf/client/leveldbstore"
	"github.com/theupdateframework/go-tuf/data"
	"github.com/theupdateframework/go-tuf/util"
)

const (
	DefaultRemoteRoot = "sigstore-tuf-root"
	TufRootEnv        = "TUF_ROOT"
	SigstoreNoCache   = "SIGSTORE_NO_CACHE"
)

type TUF struct {
	client  *client.Client
	targets targetImpl
	close   func() error
}

// We have to close the local storage passed into the tuf.Client object, but tuf.Client doesn't expose a
// Close method. So we capture the method of the inner local storage and close that.
func (t *TUF) Close() error {
	if t.close != nil {
		return t.close()
	}
	return nil
}

func NewFromEnv(ctx context.Context) (*TUF, error) {
	remote, err := GcsRemoteStore(ctx, DefaultRemoteRoot, nil, nil)
	if err != nil {
		return nil, err
	}
	return New(ctx, remote, rootCacheDir())
}

func New(ctx context.Context, remote client.RemoteStore, cacheRoot string) (*TUF, error) {
	t := &TUF{}
	// WE SHOULD:
	// FIRST RESPECT THE FILES ON DISK (BYOTUF)
	// IF THEY'RE OUT OF DATE:
	//   UPDATE THEM IN MEMORY
	//     MAYBE UPDATE THEM ON DISK
	// IF THEY DONT EXIST:
	//   THEN THE EMBEDDED ONES
	//   IF THEY'RE OUT OF DATE:
	//     UPDATE THEM IN MEMORY
	//     MAYBE UPDATE THEM ON DISK

	tufDB := filepath.Join(cacheRoot, "tuf.db")
	var local client.LocalStore
	var err error

	_, statErr := os.Stat(tufDB)
	switch {
	case os.IsNotExist(statErr):
		// There is no root at the location, try embedded
		local, err = embeddedLocalStore()
		if err != nil {
			return nil, err
		}
		t.targets = newEmbeddedImpl()
	case statErr != nil:
		// Some other error, bail
		return nil, statErr
	default:
		// There is a root! Happy path.
		local, err = localStore(tufDB)
		if err != nil {
			return nil, err
		}
		t.targets = newFileImpl()
	}

	t.client = client.NewClient(local, remote)
	// Capture the Close method on the local storage object so we can close it.
	t.close = local.Close
	trustedMeta, err := local.GetMeta()
	if err != nil {
		return nil, errors.Wrap(err, "getting trusted meta")
	}

	// We have our local store, whether it was embedded or not!
	// Now check to see if it needs to be updated.
	trustedTimestamp, ok := trustedMeta["timestamp.json"]
	if ok && !isExpiredMetadata(trustedTimestamp) {
		return t, nil
	}

	// We need to update our tufdb.
	// Warning: If a local cache already exists, you may get a local/remote mismatch
	// since the default remote may not match the remote repository configured during
	// a cosign initialize.
	trustedRoot, err := getRoot(trustedMeta)
	if err != nil {
		return nil, errors.Wrap(err, "getting trusted root")
	}
	rootKeys, rootThreshold, err := getRootKeys(trustedRoot)
	if err != nil {
		return nil, errors.Wrap(err, "bad trusted root")
	}
	if err := t.client.Init(rootKeys, rootThreshold); err != nil {
		return nil, errors.Wrap(err, "unable to initialize client, local cache may be corrupt")
	}
	if err := t.updateMetadataAndDownloadTargets(); err != nil {
		return nil, errors.Wrap(err, "updating local metadata and targets")
	}

	return t, err
}

func getRoot(meta map[string]json.RawMessage) (json.RawMessage, error) {
	trustedRoot, ok := meta["root.json"]
	if ok {
		return trustedRoot, nil
	}
	// On first initialize, there will be no root in the TUF DB, so read from embedded.
	trustedRoot, err := embeddedRootRepo.ReadFile(path.Join("repository", "root.json"))
	if err != nil {
		return nil, err
	}
	return trustedRoot, nil
}

func Initialize(remote client.RemoteStore, root []byte) error {
	tufDB := filepath.Join(rootCacheDir(), "tuf.db")
	local, err := localStore(tufDB)
	if err != nil {
		return err
	}
	defer local.Close()

	if root == nil {
		trustedMeta, err := local.GetMeta()
		if err != nil {
			return errors.Wrap(err, "getting trusted meta")
		}
		root, err = getRoot(trustedMeta)
		if err != nil {
			return errors.Wrap(err, "getting trusted root")
		}
	}
	rootKeys, rootThreshold, err := getRootKeys(root)
	if err != nil {
		return errors.Wrap(err, "bad trusted root")
	}
	c := client.NewClient(local, remote)
	if err := c.Init(rootKeys, rootThreshold); err != nil {
		return errors.Wrap(err, "initializing root")
	}
	if err := updateMetadataAndDownloadTargets(c, newFileImpl()); err != nil {
		return errors.Wrap(err, "updating local metadata and targets")
	}
	return nil
}

func (t *TUF) GetTarget(name string) ([]byte, error) {
	// Get valid target metadata. Does a local verification.
	validMeta, err := t.client.Target(name)
	if err != nil {
		return nil, errors.Wrap(err, "error verifying local metadata; local cache may be corrupt")
	}

	targetBytes, err := t.targets.Get(name)
	if err != nil {
		return nil, err
	}

	localMeta, err := util.GenerateTargetFileMeta(bytes.NewReader(targetBytes))
	if err != nil {
		return nil, err
	}
	if err := util.TargetFileMetaEqual(localMeta, validMeta); err != nil {
		return nil, err
	}

	return targetBytes, nil
}

func localStore(cacheRoot string) (client.LocalStore, error) {
	local, err := tuf_leveldbstore.FileLocalStore(cacheRoot)
	if err != nil {
		return nil, errors.Wrap(err, "creating cached local store")
	}
	return local, nil
}

func embeddedLocalStore() (client.LocalStore, error) {
	local := client.MemoryLocalStore()
	for _, mdFilename := range []string{"root.json", "targets.json", "snapshot.json", "timestamp.json"} {
		b, err := embeddedRootRepo.ReadFile(path.Join("repository", mdFilename))
		if err != nil {
			return nil, errors.Wrap(err, "reading embedded file")
		}
		if err := local.SetMeta(mdFilename, b); err != nil {
			return nil, errors.Wrap(err, "setting local meta")
		}
	}
	return local, nil
}

//go:embed repository
var embeddedRootRepo embed.FS

var isExpiredMetadata = func(metadata []byte) bool {
	s := &data.Signed{}
	if err := json.Unmarshal(metadata, s); err != nil {
		return true
	}
	sm := &signedMeta{}
	if err := json.Unmarshal(s.Signed, sm); err != nil {
		return true
	}
	return time.Until(sm.Expires) <= 0
}

type signedMeta struct {
	Type    string    `json:"_type"`
	Expires time.Time `json:"expires"`
	Version int       `json:"version"`
}

func getRootKeys(rootFileBytes []byte) ([]*data.PublicKey, int, error) {
	store := gtuf.MemoryStore(map[string]json.RawMessage{"root.json": rootFileBytes}, nil)
	repo, err := gtuf.NewRepo(store)
	if err != nil {
		return nil, 0, err
	}
	rootKeys, err := repo.RootKeys()
	if err != nil {
		return nil, 0, err
	}
	rootThreshold, err := repo.GetThreshold("root")
	return rootKeys, rootThreshold, err
}

func (t *TUF) updateMetadataAndDownloadTargets() error {
	return updateMetadataAndDownloadTargets(t.client, t.targets)
}

func updateMetadataAndDownloadTargets(c *client.Client, t targetImpl) error {
	// Download updated targets and cache new metadata and targets in ${TUF_ROOT}.
	targetFiles, err := c.Update()
	if err != nil && !client.IsLatestSnapshot(err) {
		return errors.Wrap(err, "updating tuf metadata")
	}

	// Update the in-memory targets.
	// If the cache directory is enabled, update that too.
	for name := range targetFiles {
		buf := bytes.Buffer{}
		if err := downloadRemoteTarget(name, c, &buf); err != nil {
			return err
		}
		if err := t.Set(name, buf.Bytes()); err != nil {
			return err
		}
	}

	return nil
}

func downloadRemoteTarget(name string, c *client.Client, w io.Writer) error {
	dest := targetDestination{}
	if err := c.Download(name, &dest); err != nil {
		return errors.Wrap(err, "downloading target")
	}
	_, err := io.Copy(w, &dest.buf)
	return err
}

type targetDestination struct {
	buf bytes.Buffer
}

func (t *targetDestination) Write(b []byte) (int, error) {
	return t.buf.Write(b)
}

func (t *targetDestination) Delete() error {
	t.buf = bytes.Buffer{}
	return nil
}

func rootCacheDir() string {
	rootDir := os.Getenv(TufRootEnv)
	if rootDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			home = ""
		}
		return filepath.Join(home, ".sigstore", "root")
	}
	return rootDir
}

func cachedTargetsDir(cacheRoot string) string {
	return filepath.Join(cacheRoot, "targets")
}

type targetImpl interface {
	Get(string) ([]byte, error)
	setImpl
}

type setImpl interface {
	Set(string, []byte) error
}

type memoryCache struct {
	targets map[string][]byte
}

func (m *memoryCache) Set(p string, b []byte) error {
	if m.targets == nil {
		m.targets = map[string][]byte{}
	}
	m.targets[p] = b
	return nil
}

type embedded struct {
	setImpl
}

func (e *embedded) Get(p string) ([]byte, error) {
	b, err := embeddedRootRepo.ReadFile(path.Join("repository", "targets", p))
	if err != nil {
		return nil, err
	}
	// Unfortunately go:embed appears to somehow replace our line endings on windows, we need to switch them back.
	// It should theoretically be safe to do this everywhere - but the files only seem to get mutated on Windows so
	// let's only change them back there.
	if runtime.GOOS == "windows" {
		return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")), nil
	}
	return b, nil
}

type file struct {
	base string
	setImpl
}

func (f *file) Get(p string) ([]byte, error) {
	fp := filepath.Join(f.base, p)
	return os.ReadFile(fp)
}

type diskCache struct {
	base string
}

func (d *diskCache) Set(p string, b []byte) error {
	if err := os.MkdirAll(d.base, 0700); err != nil {
		return errors.Wrap(err, "creating targets dir")
	}
	fp := filepath.Join(d.base, p)
	return os.WriteFile(fp, b, 0600)
}

func noCache() bool {
	b, err := strconv.ParseBool(os.Getenv(SigstoreNoCache))
	if err != nil {
		return false
	}
	return b
}

func newEmbeddedImpl() targetImpl {
	e := &embedded{}
	if noCache() {
		e.setImpl = &memoryCache{}
	} else {
		e.setImpl = &diskCache{base: cachedTargetsDir(rootCacheDir())}
	}
	return e
}

func newFileImpl() targetImpl {
	base := cachedTargetsDir(rootCacheDir())
	f := &file{base: base}
	if noCache() {
		f.setImpl = &memoryCache{}
	} else {
		f.setImpl = &diskCache{base: base}
	}
	return f
}
