// Copyright 2026 The Sigstore Authors.
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
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/updatekeypair"
	"github.com/spf13/cobra"
)

func UpdateKeyPair() *cobra.Command {
	o := &options.UpdateKeyPairOptions{}

	cmd := &cobra.Command{
		Use:   "update-key-pair",
		Short: "Updates the password of a private key.",
		Long:  "Re-encrypts an existing encrypted private key with a new password.",
		Example: `  cosign update-key-pair --key <key path>

  # update the password of an existing private key
  cosign update-key-pair --key cosign.key

CAVEATS:
  This command interactively prompts for the current password and then the new
  password (twice for confirmation). You can use the COSIGN_PASSWORD environment
  variable to provide the current password and COSIGN_NEW_PASSWORD to provide
  the new password non-interactively.
  Piping passwords is currently not supported.`,
		PersistentPreRun: options.BindViper,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return updatekeypair.UpdateKeyPairCmd(cmd.Context(), o.Key)
		},
	}

	o.AddFlags(cmd)
	return cmd
}
