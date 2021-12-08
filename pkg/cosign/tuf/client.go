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
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/theupdateframework/go-tuf"
	"github.com/theupdateframework/go-tuf/client"
	tuf_leveldbstore "github.com/theupdateframework/go-tuf/client/leveldbstore"
	"github.com/theupdateframework/go-tuf/data"
	"github.com/theupdateframework/go-tuf/util"
)

// TODO(asraa): Configure an environment variable so users can set their own remote
// outside of an explicit `cosign init` (e.g. when no cache is enabled).
const (
	TufRootEnv        = "TUF_ROOT"
	SigstoreNoCache   = "SIGSTORE_NO_CACHE"
	DefaultRemoteRoot = "sigstore-tuf-root"
)

//go:embed repository
var embeddedRootRepo embed.FS

// embeddedRootRepo's `embed.FS` expects unix-like path separators (i.e. `/`), even on Windows.
func embeddedReadFile(pathSegments ...string) ([]byte, error) {
	return embeddedRootRepo.ReadFile(path.Join(pathSegments...))
}
func embeddedOpenFile(pathSegments ...string) (fs.File, error) {
	return embeddedRootRepo.Open(path.Join(pathSegments...))
}

// Global TUF client.
// Uses TUF metadata and targets embedded in repository/* or cached in ${TUF_ROOT} (by default
// $HOME/.sigstore/root).
// If this metadata is invalid, e.g. expired, makes a call to the remote repository and caches
// unless SIGSTORE_NO_CACHE is set.
var rootClient *client.Client
var rootClientMu = &sync.Mutex{}

func GetEmbeddedRoot() ([]byte, error) {
	return embeddedReadFile("repository", "root.json")
}

func CosignCachedRoot() string {
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

func CosignCachedTargets() string {
	return filepath.Join(CosignCachedRoot(), "targets")
}

// Target destinations compatible with go-tuf.
type targetDestination struct {
	*os.File
}

func (t *targetDestination) Delete() error {
	t.Close()
	return nil
}

type ByteDestination struct {
	*bytes.Buffer
}

func (b *ByteDestination) Delete() error {
	b.Reset()
	return nil
}

// Retrieves a local target, either from the cached root or the embedded metadata.
func getLocalTarget(name string) (fs.File, error) {
	if f, err := os.Open(filepath.Join(CosignCachedTargets(), name)); err == nil {
		// Return local cached target
		return f, nil
	}
	return embeddedOpenFile("repository", "targets", name)
}

type signedMeta struct {
	Type    string    `json:"_type"`
	Expires time.Time `json:"expires"`
	Version int       `json:"version"`
}

func isExpiredMetadata(metadata []byte) bool {
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

// Gets the global TUF client if the directory exists.
// This will not make a remote call unless fetch is true.
func RootClient(ctx context.Context, remote client.RemoteStore, altRoot []byte) (*client.Client, error) {
	var err error
	rootClientMu.Lock()
	defer rootClientMu.Unlock()

	if rootClient == nil {
		// Local cached metadata exists, altRoot is provided, or embedded metadata is expired.
		// In these cases, we need to pull from remote and may cache locally.
		// TODO(asraa): Respect SIGSTORE_NO_CACHE.
		// Initialize the remote repository.
		if remote == nil {
			remote, err = GcsRemoteStore(ctx, DefaultRemoteRoot, nil, nil)
			if err != nil {
				return nil, err
			}
		}

		// Instantiate the global TUF client from the local embedded root or the cached root unless altRoot is provided.
		// In that case, always instantiate from altRoot.
		localCacheDBPath := filepath.Join(CosignCachedRoot(), "tuf.db")
		if _, err := os.Stat(localCacheDBPath); os.IsNotExist(err) && altRoot == nil {
			// Cache does not exist, check if the embedded metadata is currently valid.
			// TODO(asraa): Need a better way to check if local metadata is verified at this stage.
			timestamp, err := embeddedReadFile("repository", "timestamp.json")
			if err != nil {
				return nil, errors.Wrap(err, "reading local timestamp")
			}
			if !isExpiredMetadata(timestamp) {
				local := client.MemoryLocalStore()
				if err := local.SetMeta("timestamp.json", timestamp); err != nil {
					return nil, errors.Wrap(err, "setting local meta")
				}
				for _, mdFilename := range []string{"root.json", "targets.json", "snapshot.json"} {
					msg, err := embeddedReadFile("repository", mdFilename)
					if err != nil {
						return nil, errors.Wrap(err, "reading embedded meta")
					}
					if err := local.SetMeta(mdFilename, msg); err != nil {
						return nil, errors.Wrap(err, "setting local meta")
					}
				}
				rootClient = client.NewClient(local, remote)
				return rootClient, nil
			}
		}

		local, err := tuf_leveldbstore.FileLocalStore(localCacheDBPath)
		if err != nil {
			return nil, errors.Wrap(err, "creating cached local store")
		}

		// We may need to download latest metadata and targets if the cache is un-initialized or expired.
		trustedMeta, err := local.GetMeta()
		if err != nil {
			return nil, errors.Wrap(err, "getting trusted meta")
		}

		uninitializedClient := client.NewClient(local, remote)

		trustedTimestamp, ok := trustedMeta["timestamp.json"]
		if !ok || isExpiredMetadata(trustedTimestamp) {
			var trustedRoot []byte
			trustedRoot, ok := trustedMeta["root.json"]
			if !ok {
				// Use embedded root or altRoot as trusted if cached root does not exist
				if altRoot != nil {
					trustedRoot = altRoot
				} else {
					trustedRoot, err = embeddedReadFile("repository", "root.json")
					if err != nil {
						return nil, errors.Wrap(err, "reading embedded trusted root")
					}
				}
			}
			rootKeys, rootThreshold, err := getRootKeys(trustedRoot)
			if err != nil {
				return nil, errors.Wrap(err, "bad trusted root")
			}

			if err := uninitializedClient.Init(rootKeys, rootThreshold); err != nil {
				return nil, errors.Wrap(err, "initializing root client")
			}
			if err := updateMetadataAndDownloadTargets(uninitializedClient); err != nil {
				return nil, errors.Wrap(err, "updating from remote TUF repository")
			}
		}

		rootClient = uninitializedClient
	}

	return rootClient, nil
}

func getTargetHelper(name string, out client.Destination, c *client.Client, requireCoherence bool) error {
	// Get valid target metadata. Does a local verification.
	validMeta, err := c.Target(name)
	if err != nil {
		return errors.Wrap(err, "error verifying local metadata; local cache may be corrupt")
	}

	// We have valid local metadata and targets. Get embedded or cached local target.
	localTarget, err := getLocalTarget(name)
	if err != nil {
		return errors.Wrap(err, "reading local targets")
	}
	defer localTarget.Close()

	tee := io.TeeReader(localTarget, out)
	localMeta, err := util.GenerateTargetFileMeta(tee)
	if err != nil {
		return errors.Wrap(err, "generating local target metadata")
	}

	if requireCoherence {
		// If local target meta does not match the valid local meta,
		// we may want to make a network call to update the local metadata and re-download.
		if err := util.TargetFileMetaEqual(validMeta, localMeta); err != nil {
			return errors.Wrap(err, "bad local target")
		}
	}

	return nil
}

func GetTarget(ctx context.Context, name string, out client.Destination) error {
	// Reads the embedded or cached root. Fallsback on the default remote.
	// TODO(asraa): Replace default remote with a configurable environment variable.
	c, err := RootClient(ctx, nil, nil)
	if err != nil {
		return errors.Wrap(err, "retrieving trusted root; local cache may be corrupt")
	}

	// Retrieves the target and writes to out.
	return getTargetHelper(name, out, c, false /* requiresCoherence */)
}

func getRootKeys(rootFileBytes []byte) ([]*data.PublicKey, int, error) {
	store := tuf.MemoryStore(map[string]json.RawMessage{"root.json": rootFileBytes}, nil)
	repo, err := tuf.NewRepo(store)
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

func updateMetadataAndDownloadTargets(c *client.Client) error {
	// Download updated targets and cache new metadata and targets in ${TUF_ROOT}.
	targetFiles, err := c.Update()
	if err != nil && !client.IsLatestSnapshot(err) {
		return errors.Wrap(err, "updating tuf metadata")
	}
	// Download targets, if they don't already exist and match the updated metadata.
	if err := os.MkdirAll(CosignCachedTargets(), 0700); err != nil {
		return errors.Wrap(err, "creating targets dir")
	}
	for name := range targetFiles {
		if err := downloadRemoteTarget(name, c, nil); err != nil {
			return err
		}
	}
	return nil
}

func downloadRemoteTarget(name string, c *client.Client, out client.Destination) error {
	f, err := os.Create(filepath.Join(CosignCachedTargets(), name))
	if err != nil {
		return errors.Wrap(err, "creating target file")
	}
	defer f.Close()
	dest := targetDestination{f}

	if err := c.Download(name, &dest); err != nil {
		return errors.Wrap(err, "downloading target")
	}
	if out != nil {
		_, err = io.Copy(out, dest)
	}
	return err
}

// Instantiates the global TUF client. Uses the embedded (by default trusted) root in cosign
// unless a custom root is provided. This will always perform a remote call to update.
func Init(ctx context.Context, altRootBytes []byte, remote client.RemoteStore, threshold int) error {
	rootClient, err := RootClient(ctx, remote, altRootBytes)
	if err != nil {
		return errors.Wrap(err, "initializing root client")
	}
	if altRootBytes == nil {
		altRootBytes, err = GetEmbeddedRoot()
		if err != nil {
			return err
		}
	}
	rootKeys, rootThreshold, err := getRootKeys(altRootBytes)
	if err != nil {
		return errors.Wrap(err, "retrieving root keys")
	}
	// Initiates a network call to the remote.
	if err := rootClient.Init(rootKeys, rootThreshold); err != nil {
		return errors.Wrap(err, "initializing tuf client")
	}
	// Download initial targets and store in ${TUF_ROOT}/.sigstore/root/targets/.
	if err := os.MkdirAll(CosignCachedRoot(), 0755); err != nil {
		return errors.Wrap(err, "creating root dir")
	}
	if err := updateMetadataAndDownloadTargets(rootClient); err != nil {
		return errors.Wrap(err, "updating local metadata and targets")
	}

	return nil
}
