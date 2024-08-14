// Copyright 2024 The Sigstore Authors.
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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sigstore/cosign/v2/pkg/cosign/env"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	tufv1 "github.com/sigstore/sigstore/pkg/tuf"
)

func addKeyFromFile(publicKeys *TrustedTransparencyLogPubKeys, name, description string) error {
	raw, err := os.ReadFile(name)
	if err != nil {
		return fmt.Errorf("error reading alternate %s file: %w", description, err)
	}
	if err := publicKeys.AddTransparencyLogPubKey(raw); err != nil {
		return fmt.Errorf("error adding %s: %w", description, err)
	}
	return nil
}

func setTUFOpts() (*tuf.Options, error) {
	opts := tuf.DefaultOptions()
	if tufCacheDir := env.Getenv(env.VariableTUFRootDir); tufCacheDir != "" { //nolint:forbidigo
		opts.CachePath = tufCacheDir
	}
	err := setTUFMirror(opts)
	if err != nil {
		return nil, fmt.Errorf("error setting TUF mirror: %w", err)
	}
	err = setTUFRootJSON(opts)
	if err != nil {
		return nil, fmt.Errorf("error setting root: %w", err)
	}
	return opts, nil
}

func addKeyFromTUF(publicKeys *TrustedTransparencyLogPubKeys, opts *tuf.Options, name, description string) error {
	tufClient, err := tuf.New(opts)
	if err != nil {
		return fmt.Errorf("error creating TUF client: %w", err)
	}
	pubKeyBytes, err := tufClient.GetTarget(name)
	if err != nil {
		return fmt.Errorf("error fetching %s: %w", description, err)
	}
	if err := publicKeys.AddTransparencyLogPubKey(pubKeyBytes); err != nil {
		return fmt.Errorf("error adding %s: %w", description, err)
	}
	return nil
}

func legacyAddKeyFromTUF(ctx context.Context, publicKeys *TrustedTransparencyLogPubKeys, kind tufv1.UsageKind, names []string, description string) error {
	tufClient, err := tufv1.NewFromEnv(ctx)
	if err != nil {
		return fmt.Errorf("error creating legacy TUF client: %w", err)
	}
	targets, err := tufClient.GetTargetsByMeta(kind, names)
	if err != nil {
		return fmt.Errorf("error fetching %s: %w", description, err)
	}
	for _, t := range targets {
		if err := publicKeys.AddTransparencyLogPubKey(t.Target); err != nil {
			return fmt.Errorf("error adding %s: %w", description, err)
		}
	}
	return nil
}

func setTUFMirror(opts *tuf.Options) error {
	if tufMirror := env.Getenv(env.VariableTUFMirror); tufMirror != "" { //nolint:forbidigo
		opts.RepositoryBaseURL = tufMirror
		return nil
	}
	// try using the mirror set by `cosign initialize`
	cachedRemote := filepath.Join(opts.CachePath, "remote.json")
	remoteBytes, err := os.ReadFile(cachedRemote)
	if os.IsNotExist(err) {
		// could not find remote.json, use default mirror
		return nil
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
	}
	// Use defaults
	return nil
}

func useNewTUFClient() bool {
	return env.Getenv(env.VariableTUFMirror) != "" || env.Getenv(env.VariableTUFRootJSON) != "" || env.Getenv(env.VariableForceTrustedRoot) != ""
}
