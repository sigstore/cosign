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
	"os"

	"github.com/spf13/cobra"

	"github.com/sigstore/cosign/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/publickey"
)

func PublicKey() *cobra.Command {
	o := &options.PublicKeyOptions{}

	cmd := &cobra.Command{
		Use:   "public-key",
		Short: "Gets a public key from the key-pair.",
		Long:  "Gets a public key from the key-pair and\nwrites to a specified file. By default, it will write to standard out.",
		Example: `
  # extract public key from private key to a specified out file.
  cosign public-key --key <PRIVATE KEY FILE> --outfile <OUTPUT>

  # extract public key from URL.
  cosign public-key --key https://host.for/<FILE> --outfile <OUTPUT>

  # extract public key from Azure Key Vault
  cosign public-key --key azurekms://[VAULT_NAME][VAULT_URI]/[KEY]

  # extract public key from AWS KMS
  cosign public-key --key awskms://[ENDPOINT]/[ID/ALIAS/ARN]

  # extract public key from Google Cloud KMS
  cosign public-key --key gcpkms://projects/[PROJECT]/locations/global/keyRings/[KEYRING]/cryptoKeys/[KEY]

  # extract public key from Hashicorp Vault KMS
  cosign public-key --key hashivault://[KEY]

  # extract public key from GitLab with project name
  cosign public-key --key gitlab://[OWNER]/[PROJECT_NAME] <IMAGE>

  # extract public key from GitLab with project id
  cosign public-key --key gitlab://[PROJECT_ID] <IMAGE>`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if !options.OneOf(o.Key, o.SecurityKey.Use) {
				return &options.KeyParseError{}
			}
			return nil
		},
		PersistentPreRun: options.BindViper,
		RunE: func(cmd *cobra.Command, args []string) error {
			writer := publickey.NamedWriter{Name: "", Writer: nil}
			var f *os.File
			// Open output file for public key if specified.
			if o.OutFile != "" {
				writer.Name = o.OutFile
				var err error
				f, err = os.OpenFile(o.OutFile, os.O_WRONLY|os.O_CREATE, 0600)
				if err != nil {
					return err
				}
				writer.Writer = f
				defer f.Close()
			} else {
				writer.Writer = os.Stdout
			}
			pk := publickey.Pkopts{
				KeyRef: o.Key,
				Sk:     o.SecurityKey.Use,
				Slot:   o.SecurityKey.Slot,
			}
			return publickey.GetPublicKey(cmd.Context(), pk, writer, generate.GetPass)
		},
	}

	o.AddFlags(cmd)
	return cmd
}
