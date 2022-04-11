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
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
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
	client   *client.Client
	targets  targetImpl
	local    client.LocalStore
	remote   client.RemoteStore
	embedded bool   // local embedded or cache
	mirror   string // location of mirror
}

// JSON output representing the configured root status
type RootStatus struct {
	Local      string            `json:"local"`
	Remote     string            `json:"remote"`
	Expiration map[string]string `json:"expiration"`
	Targets    []string          `json:"targets"`
}

type TargetFile struct {
	Target []byte
	Status StatusKind
}

type customMetadata struct {
	Usage  UsageKind  `json:"usage"`
	Status StatusKind `json:"status"`
}

type sigstoreCustomMetadata struct {
	Sigstore customMetadata `json:"sigstore"`
}

// RemoteCache contains information to cache on the location of the remote
// repository.
type remoteCache struct {
	Mirror string `json:"mirror"`
}

// GetRootStatus gets the current root status for info logging
func GetRootStatus(ctx context.Context) (*RootStatus, error) {
	t, err := NewFromEnv(ctx)
	if err != nil {
		return nil, err
	}
	defer t.Close()
	return t.getRootStatus()
}

func (t *TUF) getRootStatus() (*RootStatus, error) {
	local := "embedded"
	if !t.embedded {
		local = rootCacheDir()
	}
	status := &RootStatus{
		Local:      local,
		Remote:     t.mirror,
		Expiration: map[string]string{},
		Targets:    []string{},
	}

	// Get targets
	targets, err := t.client.Targets()
	if err != nil {
		return nil, err
	}
	for t := range targets {
		status.Targets = append(status.Targets, t)
	}

	// Get metadata expiration
	trustedMeta, err := t.local.GetMeta()
	if err != nil {
		return nil, errors.Wrap(err, "getting trusted meta")
	}
	for role, md := range trustedMeta {
		expires, err := getExpiration(md)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("getting expiration for %s", role))
		}
		status.Expiration[role] = expires.Format(time.RFC822)
	}

	return status, nil
}

// Close closes the local TUF store. Should only be called once per client.
func (t *TUF) Close() error {
	return t.local.Close()
}

// initializeTUF creates a TUF client using the following params:
//   * embed: indicates using the embedded metadata and in-memory file updates.
//       When this is false, this uses a filesystem cache.
//   * mirror: provides a reference to a remote GCS or HTTP mirror.
//   * root: provides an external initial root.json. When this is not provided, this
//       defaults to the embedded root.json.
//   * forceUpdate: indicates checking the remote for an update, even when the local
//       timestamp.json is up to date.
func initializeTUF(ctx context.Context, embed bool, mirror string, root []byte, forceUpdate bool) (*TUF, error) {
	t := &TUF{
		mirror:   mirror,
		embedded: embed,
	}

	var err error
	if t.embedded {
		t.local, err = embeddedLocalStore()
		if err != nil {
			return nil, err
		}
		t.targets = newEmbeddedImpl()
	} else {
		tufDB := filepath.Join(rootCacheDir(), "tuf.db")
		t.local, err = localStore(tufDB)
		if err != nil {
			return nil, err
		}
		t.targets = newFileImpl()
	}

	t.remote, err = remoteFromMirror(ctx, t.mirror)
	if err != nil {
		t.Close()
		return nil, err
	}

	t.client = client.NewClient(t.local, t.remote)

	trustedMeta, err := t.local.GetMeta()
	if err != nil {
		t.Close()
		return nil, errors.Wrap(err, "getting trusted meta")
	}

	if root == nil {
		root, err = getRoot(trustedMeta)
		if err != nil {
			t.Close()
			return nil, errors.Wrap(err, "getting trusted root")
		}
	}

	if err := t.client.InitLocal(root); err != nil {
		t.Close()
		return nil, errors.Wrap(err, "unable to initialize client, local cache may be corrupt")
	}

	// We have our local store, whether it was embedded or not!
	// Now check to see if it needs to be updated.
	trustedTimestamp, ok := trustedMeta["timestamp.json"]
	if ok && !isExpiredTimestamp(trustedTimestamp) && !forceUpdate {
		return t, nil
	}

	// Update when timestamp is out of date.
	if err := t.updateMetadataAndDownloadTargets(); err != nil {
		t.Close()
		return nil, errors.Wrap(err, "updating local metadata and targets")
	}

	return t, err
}

func NewFromEnv(ctx context.Context) (*TUF, error) {
	// Get local and mirror from env
	tufDB := filepath.Join(rootCacheDir(), "tuf.db")
	var embed bool

	// Check for the current local.
	_, statErr := os.Stat(tufDB)
	switch {
	case os.IsNotExist(statErr):
		// There is no root at the location, use embedded.
		embed = true
	case statErr != nil:
		// Some other error, bail
		return nil, statErr
	default:
		// There is a root! Happy path.
		embed = false
	}

	// Check for the current remote mirror.
	mirror := DefaultRemoteRoot
	b, err := os.ReadFile(cachedRemote(rootCacheDir()))
	if err == nil {
		remoteInfo := remoteCache{}
		if err := json.Unmarshal(b, &remoteInfo); err == nil {
			mirror = remoteInfo.Mirror
		}
	}

	// Initializes a new TUF object from the local cache or defaults.
	return initializeTUF(ctx, embed, mirror, nil, false)
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
	// Initialize the client. Force an update.
	t, err := initializeTUF(ctx, false, mirror, root, true)
	if err != nil {
		return err
	}
	t.Close()

	// Store the remote for later.
	remoteInfo := &remoteCache{Mirror: mirror}
	b, err := json.Marshal(remoteInfo)
	if err != nil {
		return err
	}
	if err := os.WriteFile(cachedRemote(rootCacheDir()), b, 0600); err != nil {
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

// Get target files by a custom usage metadata tag. If there are no files found,
// use the fallback target names to fetch the targets by name.
func (t *TUF) GetTargetsByMeta(usage UsageKind, fallbacks []string) ([]TargetFile, error) {
	targets, err := t.client.Targets()
	if err != nil {
		return nil, errors.Wrap(err, "error getting targets")
	}
	var matchedTargets []TargetFile
	for name, targetMeta := range targets {
		// Skip any targets that do not include custom metadata.
		if targetMeta.Custom == nil {
			continue
		}
		var scm sigstoreCustomMetadata
		err := json.Unmarshal(*targetMeta.Custom, &scm)
		if err != nil {
			fmt.Fprintf(os.Stderr, "**Warning** Custom metadata not configured properly for target %s, skipping target\n", name)
			continue
		}
		if scm.Sigstore.Usage == usage {
			target, err := t.GetTarget(name)
			if err != nil {
				return nil, errors.Wrap(err, "error getting target by usage")
			}
			matchedTargets = append(matchedTargets, TargetFile{Target: target, Status: scm.Sigstore.Status})
		}
	}
	if len(matchedTargets) == 0 {
		for _, fallback := range fallbacks {
			target, err := t.GetTarget(fallback)
			if err != nil {
				fmt.Fprintf(os.Stderr, "**Warning** Missing fallback target %s, skipping\n", fallback)
				continue
			}
			matchedTargets = append(matchedTargets, TargetFile{Target: target, Status: Active})
		}
	}
	if len(matchedTargets) == 0 {
		return matchedTargets, fmt.Errorf("no matching targets by custom metadata, fallbacks not found: %s", strings.Join(fallbacks, ", "))
	}
	return matchedTargets, nil
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

func getExpiration(metadata []byte) (*time.Time, error) {
	s := &data.Signed{}
	if err := json.Unmarshal(metadata, s); err != nil {
		return nil, err
	}
	sm := &data.Timestamp{}
	if err := json.Unmarshal(s.Signed, sm); err != nil {
		return nil, err
	}
	return &sm.Expires, nil
}

var isExpiredTimestamp = func(metadata []byte) bool {
	expiration, err := getExpiration(metadata)
	if err != nil {
		return true
	}
	return time.Until(*expiration) <= 0
}

func (t *TUF) updateMetadataAndDownloadTargets() error {
	// Download updated targets and cache new metadata and targets in ${TUF_ROOT}.
	targetFiles, err := t.client.Update()
	if err != nil && !client.IsLatestSnapshot(err) {
		return errors.Wrap(err, "updating tuf metadata")
	}

	// Update the in-memory targets.
	// If the cache directory is enabled, update that too.
	for name := range targetFiles {
		buf := bytes.Buffer{}
		if err := downloadRemoteTarget(name, t.client, &buf); err != nil {
			return err
		}
		if err := t.targets.Set(name, buf.Bytes()); err != nil {
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
	return filepath.Join(cacheRoot, "remote.json")
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

func remoteFromMirror(ctx context.Context, mirror string) (client.RemoteStore, error) {
	if _, parseErr := url.ParseRequestURI(mirror); parseErr != nil {
		return GcsRemoteStore(ctx, mirror, nil, nil)
	}
	return client.HTTPRemoteStore(mirror, nil, nil)
}
