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
	"github.com/sigstore/cosign/cmd/cosign/cli/dockerfile"
	"github.com/sigstore/cosign/cmd/cosign/cli/verify"
	"github.com/spf13/cobra"

	"github.com/sigstore/cosign/cmd/cosign/cli/options"
)

func Dockerfile() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dockerfile",
		Short: "Provides utilities for discovering images in and performing operations on Dockerfiles",
	}

	cmd.AddCommand(
		dockerfileVerify(),
	)

	return cmd
}

func dockerfileVerify() *cobra.Command {
	o := &options.VerifyDockerfileOptions{}

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a signature on the base image specified in the Dockerfile",
		Long: `Verify signature and annotations on images in a Dockerfile by checking claims
against the transparency log.

Shell-like variables in the Dockerfile's FROM lines will be substituted with values from the OS ENV.`,
		Example: `  cosign dockerfile verify --key <key path>|<key url>|<kms uri> <path/to/Dockerfile>

  # verify cosign claims and signing certificates on the FROM images in the Dockerfile
  cosign dockerfile verify <path/to/Dockerfile>

  # only verify the base image (the last FROM image)
  cosign dockerfile verify --base-image-only <path/to/Dockerfile>

  # additionally verify specified annotations
  cosign dockerfile verify -a key1=val1 -a key2=val2 <path/to/Dockerfile>

  # (experimental) additionally, verify with the transparency log
  COSIGN_EXPERIMENTAL=1 cosign dockerfile verify <path/to/Dockerfile>

  # verify images with public key
  cosign dockerfile verify --key cosign.pub <path/to/Dockerfile>

  # verify images with public key provided by URL
  cosign dockerfile verify --key https://host.for/<FILE> <path/to/Dockerfile>

  # verify images with public key stored in Azure Key Vault
  cosign dockerfile verify --key azurekms://[VAULT_NAME][VAULT_URI]/[KEY] <path/to/Dockerfile>

  # verify images with public key stored in AWS KMS
  cosign dockerfile verify --key awskms://[ENDPOINT]/[ID/ALIAS/ARN] <path/to/Dockerfile>

  # verify images with public key stored in Google Cloud KMS
  cosign dockerfile verify --key gcpkms://projects/[PROJECT]/locations/global/keyRings/[KEYRING]/cryptoKeys/[KEY] <path/to/Dockerfile>

  # verify images with public key stored in Hashicorp Vault
  cosign dockerfile verify --key hashivault://[KEY] <path/to/Dockerfile>`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			annotations, err := o.AnnotationsMap()
			if err != nil {
				return err
			}
			v := &dockerfile.VerifyDockerfileCommand{
				VerifyCommand: verify.VerifyCommand{
					RegistryOptions: o.Registry,
					CheckClaims:     o.CheckClaims,
					KeyRef:          o.Key,
					CertRef:         o.CertVerify.Cert,
					CertEmail:       o.CertVerify.CertEmail,
					CertOidcIssuer:  o.CertVerify.CertOidcIssuer,
					Sk:              o.SecurityKey.Use,
					Slot:            o.SecurityKey.Slot,
					Output:          o.Output,
					RekorURL:        o.Rekor.URL,
					Attachment:      o.Attachment,
					Annotations:     annotations,
				},
				BaseOnly: o.BaseImageOnly,
			}
			return v.Exec(cmd.Context(), args)
		},
	}

	o.AddFlags(cmd)

	return cmd
}
