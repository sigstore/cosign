// Copyright 2025 The Sigstore Authors.
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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sigstore/cosign/v2/pkg/cosign/env"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
)

func TrustedRoot() (root.TrustedMaterial, error) {
	opts, err := setTUFOpts()
	if err != nil {
		return nil, fmt.Errorf("error setting TUF options: %w", err)
	}
	tr, err := root.NewLiveTrustedRoot(opts)
	if err != nil {
		return nil, fmt.Errorf("error getting live trusted root: %w", err)
	}
	return tr, nil
}

func SigningConfig() (*root.SigningConfig, error) {
	opts, err := setTUFOpts()
	if err != nil {
		return nil, fmt.Errorf("error setting TUF options: %w", err)
	}
	sc, err := root.FetchSigningConfigWithOptions(opts)
	if err != nil {
		return nil, fmt.Errorf("error getting signing config from TUF: %w", err)
	}
	return sc, nil
}

// setTUFOpts sets the TUF cache directory, the mirror URL, and the root.json in the TUF options.
// The cache directory is provided by the user as an environment variable TUF_ROOT, or the default $HOME/.sigstore/root is used.
// The mirror URL is provided by the user as an environment variable TUF_MIRROR. If not overridden by the user, the value set during `cosign initialize` in remote.json in the cache directory is used.
// If the mirror happens to be the sigstore.dev production TUF CDN, the options are returned since it is safe to use all the default settings.
// If the mirror is a custom mirror, we try to find a cached root.json. We must not use the default embedded root.json.
// If the TUF options cannot be found through these steps, the caller should not try to use this TUF client to fetch the trusted root and should instead fall back to the legacy TUF client to fetch individual trusted keys.
func setTUFOpts() (*tuf.Options, error) {
	opts := tuf.DefaultOptions()
	if tufCacheDir := env.Getenv(env.VariableTUFRootDir); tufCacheDir != "" { //nolint:forbidigo
		opts.CachePath = tufCacheDir
	}
	err := setTUFMirror(opts)
	if err != nil {
		return nil, fmt.Errorf("error setting TUF mirror: %w", err)
	}
	if opts.RepositoryBaseURL == tuf.DefaultMirror {
		// Using the default mirror, so just use the embedded root.json.
		return opts, nil
	}
	err = setTUFRootJSON(opts)
	if err != nil {
		return nil, fmt.Errorf("error setting root: %w", err)
	}
	return opts, nil
}

func setTUFMirror(opts *tuf.Options) error {
	if tufMirror := env.Getenv(env.VariableTUFMirror); tufMirror != "" { //nolint:forbidigo
		opts.RepositoryBaseURL = tufMirror
		return nil
	}
	// try using the mirror set by `cosign initialize`
	cachedRemote := filepath.Join(opts.CachePath, "remote.json")
	remoteBytes, err := os.ReadFile(cachedRemote)
	if errors.Is(err, os.ErrNotExist) {
		return nil // `cosign initialize` wasn't run, so use the default
	}
	if err != nil {
		return fmt.Errorf("error reading remote.json: %w", err)
	}
	remote := make(map[string]string)
	err = json.Unmarshal(remoteBytes, &remote)
	if err != nil {
		return fmt.Errorf("error unmarshalling remote.json: %w", err)
	}
	opts.RepositoryBaseURL = remote["mirror"]
	return nil
}

func setTUFRootJSON(opts *tuf.Options) error {
	// TUF root set by TUF_ROOT_JSON
	if tufRootJSON := env.Getenv(env.VariableTUFRootJSON); tufRootJSON != "" { //nolint:forbidigo
		rootJSONBytes, err := os.ReadFile(tufRootJSON)
		if err != nil {
			return fmt.Errorf("error reading root.json given by TUF_ROOT_JSON")
		}
		opts.Root = rootJSONBytes
		return nil
	}
	// Look for cached root.json
	cachedRootJSON := filepath.Join(opts.CachePath, tuf.URLToPath(opts.RepositoryBaseURL), "root.json")
	if _, err := os.Stat(cachedRootJSON); !os.IsNotExist(err) {
		rootJSONBytes, err := os.ReadFile(cachedRootJSON)
		if err != nil {
			return fmt.Errorf("error reading cached root.json")
		}
		opts.Root = rootJSONBytes
		return nil
	}
	return fmt.Errorf("could not find cached root.json")
}
