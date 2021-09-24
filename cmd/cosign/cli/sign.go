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
	"flag"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/sigstore/cosign/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
)

func addSign(topLevel *cobra.Command) {
	o := &options.SignOptions{}

	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign the supplied container image.\ncosign sign --key <key path>|<kms uri> [--payload <path>] [-a key=value] [--upload=true|false] [-f] [-r] <image uri>",
		Long:  "Sign the supplied container image.",
		Example: `
  # sign a container image with Google sign-in (experimental)
  COSIGN_EXPERIMENTAL=1 cosign sign <IMAGE>

  # sign a container image with a local key pair file
  cosign sign --key cosign.key <IMAGE>

  # sign a multi-arch container image AND all referenced, discrete images
  cosign sign --key cosign.key --r <MULTI-ARCH IMAGE>

  # sign a container image and add annotations
  cosign sign --key cosign.key -a key1=value1 -a key2=value2 <IMAGE>

  # sign a container image with a key pair stored in Azure Key Vault
  cosign sign --key azurekms://[VAULT_NAME][VAULT_URI]/[KEY] <IMAGE>

  # sign a container image with a key pair stored in AWS KMS
  cosign sign --key awskms://[ENDPOINT]/[ID/ALIAS/ARN] <IMAGE>

  # sign a container image with a key pair stored in Google Cloud KMS
  cosign sign --key gcpkms://projects/[PROJECT]/locations/global/keyRings/[KEYRING]/cryptoKeys/[KEY]/versions/[VERSION] <IMAGE>

  # sign a container image with a key pair stored in Hashicorp Vault
  cosign sign --key hashivault://[KEY] <IMAGE>

  # sign a container image with a key pair stored in a Kubernetes secret
  cosign sign --key k8s://[NAMESPACE]/[KEY] <IMAGE>

  # sign a container in a registry which does not fully support OCI media types
  COSIGN_DOCKER_MEDIA_TYPES=1 cosign sign --key cosign.key legacy-registry.example.com/my/image`,

		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return flag.ErrHelp
			}
			switch o.Attachment {
			case "sbom", "":
				break
			default:
				return flag.ErrHelp
			}
			ko := sign.KeyOpts{
				KeyRef:           o.Key,
				PassFunc:         generate.GetPass,
				Sk:               o.SecurityKey.Use,
				Slot:             o.SecurityKey.Slot,
				FulcioURL:        o.Fulcio.URL,
				IDToken:          o.Fulcio.IdentityToken,
				RekorURL:         o.Rektor.URL,
				OIDCIssuer:       o.OIDC.Issuer,
				OIDCClientID:     o.OIDC.ClientID,
				OIDCClientSecret: o.OIDC.ClientSecret,
			}
			annotationsMap, err := o.AnnotationsMap()
			if err != nil {
				return err
			}
			if err := sign.SignCmd(cmd.Context(), ko, o.RegistryOpts, annotationsMap.Annotations, args, o.Cert, o.Upload, o.PayloadPath, o.Force, o.Recursive, o.Attachment); err != nil {
				if o.Attachment == "" {
					return errors.Wrapf(err, "signing %v", args)
				}
				return errors.Wrapf(err, "signing attachement %s for image %v", o.Attachment, args)
			}
			return nil
		},
	}

	options.AddSignOptions(cmd, o)
	topLevel.AddCommand(cmd)
}
