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
	"strings"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/pkg/blob"
	"github.com/sigstore/sigstore/pkg/tuf"
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

	if err := tuf.Initialize(ctx, mirror, rootFileBytes); err != nil {
		return err
	}

	status, err := tuf.GetRootStatus(ctx)
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
