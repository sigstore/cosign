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

	"github.com/sigstore/cosign/pkg/blob"
	"github.com/sigstore/cosign/pkg/cosign/tuf"
)

func DoInitialize(ctx context.Context, root, mirror string, threshold int) error {
	// Get the initial trusted root contents.
	var rootFileBytes []byte
	var err error
	if root != "" {
		rootFileBytes, err = blob.LoadFileOrURL(root)
		if err != nil {
			return err
		}
	} else {
		rootFileBytes, err = tuf.GetEmbeddedRoot()
		if err != nil {
			return err
		}
	}

	// Initialize the remote repository.
	remote, err := tuf.GcsRemoteStore(ctx, mirror, nil, nil)
	if err != nil {
		return err
	}

	// Initialize and update the local SigStore root.
	return tuf.Init(ctx, rootFileBytes, remote, threshold)
}
