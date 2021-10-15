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
	"github.com/sigstore/cosign/cmd/cosign/cli/initialize"
	"github.com/spf13/cobra"

	"github.com/sigstore/cosign/cmd/cosign/cli/options"
)

func Initialize() *cobra.Command {
	o := &options.InitializeOptions{}

	cmd := &cobra.Command{
		Use:   "initialize",
		Short: "Initializes SigStore root to retrieve trusted certificate and key targets for verification.",
		Long: `Initializes SigStore root to retrieve trusted certificate and key targets for verification.

The following options are used by default:
	- The current trusted Sigstore TUF root is embedded inside cosign at the time of release.
	- SigStore remote TUF repository is pulled from the GCS mirror at sigstore-tuf-root.
	- A default threshold of 3 root signatures is used.

To provide an out-of-band trusted initial root.json, use the -root flag with a file or URL reference.
This will enable you to point cosign to a separate TUF root.

Any updated TUF repository will be written to $HOME/.sigstore/root/.

Trusted keys and certificate used in cosign verification (e.g. verifying Fulcio issued certificates
with Fulcio root CA) are pulled form the trusted metadata.`,
		Example: `cosign initialize -mirror <url> -out <file>

# initialize root with distributed root keys, default mirror, and default out path.
cosign initialize

# initialize with an out-of-band root key file, using the default mirror.
cosign initialize -root <url>

# initialize with an out-of-band root key file and custom repository mirror.
cosign initialize -mirror <url> -root <url>`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return initialize.DoInitialize(cmd.Context(), o.Root, o.Mirror, o.Threshold)
		},
	}

	o.AddFlags(cmd)
	return cmd
}
