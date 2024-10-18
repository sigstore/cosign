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

package initialize

import (
	"context"
	_ "embed" // To enable the `go:embed` directive.
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/internal/ui"
	"github.com/sigstore/cosign/v2/pkg/blob"
	"github.com/sigstore/cosign/v2/pkg/cosign/env"
	tufroot "github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	tufv1 "github.com/sigstore/sigstore/pkg/tuf"
)

func DoInitialize(ctx context.Context, root, mirror string) error {
	return doInitialize(ctx, root, mirror, "", true)
}

func DoInitializeWithRootChecksum(ctx context.Context, root, mirror, rootChecksum string) error {
	return doInitialize(ctx, root, mirror, rootChecksum, false)
}

func doInitialize(ctx context.Context, root, mirror, rootChecksum string, forceSkipChecksumValidation bool) error {
	// Get the initial trusted root contents.
	var rootFileBytes []byte
	var err error
	if root != "" {
		if !forceSkipChecksumValidation {
			if rootChecksum == "" && (strings.HasPrefix(root, "http://") || strings.HasPrefix(root, "https://")) {
				fmt.Fprintln(os.Stderr, options.RootWithoutChecksumDeprecation)
			}
		}
		verifyChecksum := !forceSkipChecksumValidation && (rootChecksum != "")
		if verifyChecksum {
			rootFileBytes, err = blob.LoadFileOrURLWithChecksum(root, rootChecksum)
		} else {
			rootFileBytes, err = blob.LoadFileOrURL(root)
		}
		if err != nil {
			return err
		}
	}

	opts := tuf.DefaultOptions()
	if root != "" {
		opts.Root = rootFileBytes
	}
	if mirror != "" {
		opts.RepositoryBaseURL = mirror
	}
	if tufCacheDir := env.Getenv(env.VariableTUFRootDir); tufCacheDir != "" { //nolint:forbidigo
		opts.CachePath = tufCacheDir
	}

	// Leave a hint for where the current remote is. Adopted from sigstore/sigstore TUF client.
	remote := map[string]string{"mirror": opts.RepositoryBaseURL}
	remoteBytes, err := json.Marshal(remote)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(opts.CachePath, 0o700); err != nil {
		return fmt.Errorf("creating cache directory: %w", err)
	}
	if err := os.WriteFile(filepath.FromSlash(filepath.Join(opts.CachePath, "remote.json")), remoteBytes, 0o600); err != nil {
		return fmt.Errorf("storing remote: %w", err)
	}

	trustedRoot, err := tufroot.NewLiveTrustedRoot(opts)
	if err != nil {
		ui.Warnf(ctx, "Could not fetch trusted_root.json from the TUF mirror (encountered error: %v), falling back to individual targets. It is recommended to update your TUF metadata repository to include trusted_root.json.", err)
	}
	if trustedRoot != nil {
		return nil
	}

	// The mirror did not have a trusted_root.json, so initialize the legacy TUF targets.
	if err := tufv1.Initialize(ctx, mirror, rootFileBytes); err != nil {
		return err
	}

	status, err := tufv1.GetRootStatus(ctx)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(status, "", "\t")
	if err != nil {
		return err
	}

	fmt.Println("Root status: \n", string(b))
	return nil
}
