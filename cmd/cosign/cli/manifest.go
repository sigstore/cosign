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
	"github.com/sigstore/cosign/cmd/cosign/cli/manifest"
	"github.com/sigstore/cosign/cmd/cosign/cli/verify"
	"github.com/spf13/cobra"

	"github.com/sigstore/cosign/cmd/cosign/cli/options"
)

func Manifest() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "manifest",
		Short: "Provides utilities for discovering images in and performing operations on Kubernetes manifests",
	}

	cmd.AddCommand(
		manifestVerify(),
	)

	return cmd
}

func manifestVerify() *cobra.Command {
	o := &options.VerifyOptions{}

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify all signatures of images specified in the manifest",
		Long: `Verify all signature of images in a Kubernetes resource manifest by checking claims
against the transparency log.`,
		Example: `  cosign manifest verify --key <key path>|<key url>|<kms uri> <path/to/manifest>

  # verify cosign claims and signing certificates on images in the manifest
  cosign manifest verify <path/to/my-deployment.yaml>

  # additionally verify specified annotations
  cosign manifest verify -a key1=val1 -a key2=val2 <path/to/my-deployment.yaml>

  # (experimental) additionally, verify with the transparency log
  COSIGN_EXPERIMENTAL=1 cosign manifest verify <path/to/my-deployment.yaml>

  # verify images with public key
  cosign manifest verify --key cosign.pub <path/to/my-deployment.yaml>

  # verify images with public key provided by URL
  cosign manifest verify --key https://host.for/<FILE> <path/to/my-deployment.yaml>

  # verify images with public key stored in Azure Key Vault
  cosign manifest verify --key azurekms://[VAULT_NAME][VAULT_URI]/[KEY] <path/to/my-deployment.yaml>

  # verify images with public key stored in AWS KMS
  cosign manifest verify --key awskms://[ENDPOINT]/[ID/ALIAS/ARN] <path/to/my-deployment.yaml>

  # verify images with public key stored in Google Cloud KMS
  cosign manifest verify --key gcpkms://projects/[PROJECT]/locations/global/keyRings/[KEYRING]/cryptoKeys/[KEY] <path/to/my-deployment.yaml>

  # verify images with public key stored in Hashicorp Vault
  cosign manifest verify --key hashivault://[KEY] <path/to/my-deployment.yaml>`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			annotations, err := o.AnnotationsMap()
			if err != nil {
				return err
			}
			v := &manifest.VerifyManifestCommand{
				VerifyCommand: verify.VerifyCommand{
					RegistryOptions: o.Registry,
					CheckClaims:     o.CheckClaims,
					KeyRef:          o.Key,
					CertRef:         o.CertVerify.Cert,
					CertEmail:       o.CertVerify.CertEmail,
					CertOidcIssuer:  o.CertVerify.CertOidcIssuer,
					CertChain:       o.CertVerify.CertChain,
					Sk:              o.SecurityKey.Use,
					Slot:            o.SecurityKey.Slot,
					Output:          o.Output,
					RekorURL:        o.Rekor.URL,
					Attachment:      o.Attachment,
					Annotations:     annotations,
				},
			}
			return v.Exec(cmd.Context(), args)
		},
	}

	o.AddFlags(cmd)

	return cmd
}
