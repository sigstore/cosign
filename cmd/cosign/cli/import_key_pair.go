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
	"github.com/spf13/cobra"

	"github.com/sigstore/cosign/cmd/cosign/cli/importkeypair"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
)

func ImportKeyPair() *cobra.Command {
	o := &options.ImportKeyPairOptions{}

	cmd := &cobra.Command{
		Use:   "import-key-pair",
		Short: "Imports an RSA or EC key-pair.",
		Long:  "Imports an RSA or EC key-pair for signing.",
		Example: `  cosign import-key-pair

  # import key-pair and write to import-cosign.key and import-cosign.pub files
  cosign import-key-pair

CAVEATS:
  This command interactively prompts for a password. You can use
  the COSIGN_PASSWORD environment variable to provide one.`,

		RunE: func(cmd *cobra.Command, args []string) error {
			return importkeypair.ImportKeyPairCmd(cmd.Context(), o.Key, args)
		},
	}

	o.AddFlags(cmd)
	return cmd
}
