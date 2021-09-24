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

	"github.com/sigstore/cosign/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
)

func addGenerateKeyPair(topLevel *cobra.Command) {
	o := &options.GenerateKeyPairOptions{}

	cmd := &cobra.Command{
		Use:   "generate-key-pair",
		Short: "Generates a key-pair.\ncosign generate-key-pair [--kms KMSPATH]",
		Long:  "Generates a key-pair for signing.",
		Example: `
  # generate key-pair and write to cosign.key and cosign.pub files
  cosign generate-key-pair

  # generate a key-pair in Azure Key Vault
  cosign generate-key-pair --kms azurekms://[VAULT_NAME][VAULT_URI]/[KEY]

  # generate a key-pair in AWS KMS
  cosign generate-key-pair --kms awskms://[ENDPOINT]/[ID/ALIAS/ARN]

  # generate a key-pair in Google Cloud KMS
  cosign generate-key-pair --kms gcpkms://projects/[PROJECT]/locations/global/keyRings/[KEYRING]/cryptoKeys/[KEY]

  # generate a key-pair in Hashicorp Vault
  cosign generate-key-pair --kms hashivault://[KEY]

  # generate a key-pair in Kubernetes Secret
  cosign generate-key-pair k8s://[NAMESPACE]/[NAME]

CAVEATS:
  This command interactively prompts for a password. You can use
  the COSIGN_PASSWORD environment variable to provide one.`,

		RunE: func(cmd *cobra.Command, args []string) error {
			return generate.GenerateKeyPairCmd(cmd.Context(), o.KMS, args)
		},
	}

	options.AddGenerateKeyPairOptions(cmd, o)
	topLevel.AddCommand(cmd)
}
