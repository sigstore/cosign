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
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/sigstore/cosign/cmd/cosign/cli/attest"
	"github.com/sigstore/cosign/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
)

func Attest() *cobra.Command {
	o := &options.AttestOptions{}

	cmd := &cobra.Command{
		Use:   "attest",
		Short: "Attest the supplied container image.",
		Example: `  cosign attest --key <key path>|<kms uri> [--predicate <path>] [--a key=value] [--no-upload=true|false] [--f] [--r] <image uri>

  # attach an attestation to a container image Google sign-in (experimental)
  COSIGN_EXPERIMENTAL=1 cosign attest --timeout 90s --predicate <FILE> --type <TYPE> <IMAGE>

  # attach an attestation to a container image with a local key pair file
  cosign attest --predicate <FILE> --type <TYPE> --key cosign.key <IMAGE>

  # attach an attestation to a container image with a key pair stored in Azure Key Vault
  cosign attest --predicate <FILE> --type <TYPE> --key azurekms://[VAULT_NAME][VAULT_URI]/[KEY] <IMAGE>

  # attach an attestation to a container image with a key pair stored in AWS KMS
  cosign attest --predicate <FILE> --type <TYPE> --key awskms://[ENDPOINT]/[ID/ALIAS/ARN] <IMAGE>

  # attach an attestation to a container image with a key pair stored in Google Cloud KMS
  cosign attest --predicate <FILE> --type <TYPE> --key gcpkms://projects/[PROJECT]/locations/global/keyRings/[KEYRING]/cryptoKeys/[KEY]/versions/[VERSION] <IMAGE>

  # attach an attestation to a container image with a key pair stored in Hashicorp Vault
  cosign attest --predicate <FILE> --type <TYPE> --key hashivault://[KEY] <IMAGE>

  # attach an attestation to a container image which does not fully support OCI media types
  COSIGN_DOCKER_MEDIA_TYPES=1 cosign attest --predicate <FILE> --type <TYPE> --key cosign.key legacy-registry.example.com/my/image`,

		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ko := sign.KeyOpts{
				KeyRef:                   o.Key,
				PassFunc:                 generate.GetPass,
				Sk:                       o.SecurityKey.Use,
				Slot:                     o.SecurityKey.Slot,
				FulcioURL:                o.Fulcio.URL,
				IDToken:                  o.Fulcio.IdentityToken,
				InsecureSkipFulcioVerify: o.Fulcio.InsecureSkipFulcioVerify,
				RekorURL:                 o.Rekor.URL,
				OIDCIssuer:               o.OIDC.Issuer,
				OIDCClientID:             o.OIDC.ClientID,
				OIDCClientSecret:         o.OIDC.ClientSecret,
			}
			for _, img := range args {
				if err := attest.AttestCmd(cmd.Context(), ko, o.Registry, img, o.Cert, o.NoUpload,
					o.Predicate.Path, o.Force, o.Predicate.Type, o.Replace, ro.Timeout); err != nil {
					return errors.Wrapf(err, "signing %s", img)
				}
			}
			return nil
		},
	}
	o.AddFlags(cmd)
	return cmd
}
