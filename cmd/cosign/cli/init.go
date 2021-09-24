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
	_ "embed" // To enable the `go:embed` directive.
	"flag"

	"github.com/peterbourgon/ff/v3/ffcli"

	"github.com/sigstore/cosign/pkg/blob"
	ctuf "github.com/sigstore/cosign/pkg/cosign/tuf"
)

//go:embed 1.root.json
var initialRoot string

func Init() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign init", flag.ExitOnError)
		// TODO: Support HTTP mirrors as well
		mirror    = flagset.String("mirror", "sigstore-tuf-root", "GCS bucket to a SigStore TUF repository.")
		root      = flagset.String("root", "", "path to trusted initial root. defaults to embedded root.")
		threshold = flagset.Int("threshold", 3, "threshold of root key signers")
	)
	return &ffcli.Command{
		Name:       "init",
		ShortUsage: "cosign init -mirror <url> -out <file>",
		ShortHelp:  `Initializes SigStore root to retrieve trusted certificate and key targets for verification.`,
		LongHelp: `Initializes SigStore root to retrieve trusted certificate and key targets for verification.

The following options are used by default:
	- The initial 1.root.json is embedded inside cosign.
	- SigStore current TUF repository is pulled from the GCS mirror at sigstore-tuf-root.
	- A default threshold of 3 root signatures is used. 

To provide an out-of-band trusted initial root.json, use the -root flag with a file or URL reference.

The resulting updated TUF repository will be written to $HOME/.sigstore/root/. 

Trusted keys and certificate used in cosign verification (e.g. verifying Fulcio issued certificates 
with Fulcio root CA) are pulled form the trusted metadata.

EXAMPLES
  # initialize root with distributed root keys, default mirror, and default out path.
  cosign init

  # initialize with an out-of-band root key file.
  cosign init

  # initialize with an out-of-band root key file and custom repository mirror.
  cosign init -mirror <url> -root <url>
  `,
		FlagSet: flagset,
		Exec: func(ctx context.Context, args []string) error {
			// Get the initial trusted root contents.
			var rootFileBytes []byte
			if *root == "" {
				rootFileBytes = []byte(initialRoot)
			} else {
				var err error
				rootFileBytes, err = blob.LoadFileOrURL(*root)
				if err != nil {
					return err
				}
			}

			// Initialize the remote repository.
			remote, err := ctuf.GcsRemoteStore(ctx, *mirror, nil, nil)
			if err != nil {
				return err
			}

			// Initialize and update the local SigStore root.
			return ctuf.Init(ctx, rootFileBytes, remote, *threshold)
		},
	}
}
