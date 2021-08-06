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

package cli

import (
	"context"
	"flag"

	"github.com/peterbourgon/ff/v3/ffcli"
	ctuf "github.com/sigstore/cosign/pkg/cosign/tuf"
)

func Init() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign init", flag.ExitOnError)
		// TODO: Support HTTP mirrors as well
		mirror    = flagset.String("mirror", "test-root-123", "GCS bucket to a SigStore TUF repository.")
		root      = flagset.String("root", ".sigstore/keys.json", "path to trusted initial root.")
		threshold = flagset.Int("threshold", 3, "threshold of root key signers")
	)
	return &ffcli.Command{
		Name:       "init",
		ShortUsage: "cosign init -mirror <url> -out <file>",
		ShortHelp:  `Initializes SigStore root to retrieve trusted certificate and key targets for verification.`,
		LongHelp: `Initializes SigStore root to retrieve trusted certificate and key targets for verification.

The following options are used by default:
	- Initial root keys are pulled from .sigstore/keys. If it does not exist, uses root keys provided in the release.
	- SigStore current TUF repository is pulled from the GCS mirror at .
	- Resulting trusted metadata is written to .sigstore/root.

To provide an out-of-band trusted root.json, copy the file into a directory named .sigstore/root/.

The resulting updated TUF repository will be written to .sigstore/root/. 

Trusted keys and certificate used in cosign verification (e.g. verifying Fulcio issued certificates 
with Fulcio root CA) are pulled form the trusted metadata.

EXAMPLES
  # initialize root with distributed root keys, default mirror, and default out path.
  cosign init

  # initialize with an out-of-band root key file.
  cosign init

  # initialize with an out-of-band root key file and custom repository mirror.
  cosign init-mirror <>
  `,
		FlagSet: flagset,
		Exec: func(ctx context.Context, args []string) error {
			// Initialize the remote repository.
			remote, err := ctuf.GcsRemoteStore(ctx, *mirror, nil, nil)
			if err != nil {
				return err
			}

			// Initialize and update the local SigStore root.
			return ctuf.Init(context.Background(), *root, remote, *threshold)
		},
	}
}
