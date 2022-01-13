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
	"net/url"
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
	local   client.LocalStore
	remote  client.RemoteStore
}

// Close closes the local TUF store. Should only be called once per client.
func (t *TUF) Close() error {
	return t.local.Close()
}

func NewFromEnv(ctx context.Context) (*TUF, error) {
	// Initializes a new TUF object from the local cache or defaults.
	t, err := newTuf(ctx)
	if err != nil {
		return nil, err
	}

	trustedMeta, err := t.local.GetMeta()
	if err != nil {
		return nil, errors.Wrap(err, "getting trusted meta")
	}

	// We have our local store, whether it was embedded or not!
	// Now check to see if it needs to be updated.
	trustedTimestamp, ok := trustedMeta["timestamp.json"]
	if ok && !isExpiredTimestamp(trustedTimestamp) {
		return t, nil
	}

	// We need to update our tufdb.
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

func Initialize(ctx context.Context, mirror string, root []byte) error {
	// Initialize the remote repository.
	remote, err := remoteFromMirror(ctx, mirror)
	if err != nil {
		return err
	}

	// Initialize the local.
	tufDB := filepath.Join(rootCacheDir(), "tuf.db")
	local, err := localStore(tufDB)
	if err != nil {
		return err
	}
	defer local.Close()

	// Initialize the client.
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
	// Timestamp does not need to be saved in memory on Initialize
	if err := updateMetadataAndDownloadTargets(c, newFileImpl()); err != nil {
		return errors.Wrap(err, "updating local metadata and targets")
	}
	// Store the remote for later.
	if err := os.WriteFile(cachedRemote(rootCacheDir()), []byte(mirror), 0600); err != nil {
		return errors.Wrap(err, "storing remote")
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

func (t *TUF) GetTimestamp() ([]byte, error) {
	trustedMeta, err := t.local.GetMeta()
	if err != nil {
		return nil, errors.Wrap(err, "getting trusted meta")
	}
	timestamp, ok := trustedMeta["timestamp.json"]
	if !ok || len(timestamp) == 0 {
		return nil, errors.New("unable to get TUF timestamp")
	}
	return timestamp, nil
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

var isExpiredTimestamp = func(metadata []byte) bool {
	s := &data.Signed{}
	if err := json.Unmarshal(metadata, s); err != nil {
		return true
	}
	sm := &data.Timestamp{}
	if err := json.Unmarshal(s.Signed, sm); err != nil {
		return true
	}
	return time.Until(sm.Expires) <= 0
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

func cachedRemote(cacheRoot string) string {
	return filepath.Join(cacheRoot, "remote.txt")
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

func newTuf(ctx context.Context) (*TUF, error) {
	t := &TUF{}
	tufDB := filepath.Join(rootCacheDir(), "tuf.db")
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
	t.local = local

	// If there's a remote defined in the cache, use it. Otherwise, use the
	// default remote root.
	b, err := os.ReadFile(cachedRemote(rootCacheDir()))
	mirror := string(b)
	if err != nil {
		mirror = DefaultRemoteRoot
	}
	remote, err := remoteFromMirror(ctx, mirror)
	if err != nil {
		return nil, err
	}
	t.remote = remote

	t.client = client.NewClient(local, t.remote)
	return t, nil
}

func remoteFromMirror(ctx context.Context, mirror string) (client.RemoteStore, error) {
	if _, parseErr := url.ParseRequestURI(mirror); parseErr != nil {
		return GcsRemoteStore(ctx, mirror, nil, nil)
	}
	return client.HTTPRemoteStore(mirror, nil, nil)
}
