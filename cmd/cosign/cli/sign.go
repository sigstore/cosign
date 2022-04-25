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

func Sign() *cobra.Command {
	o := &options.SignOptions{}

	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign the supplied container image.",
		Long:  "Sign the supplied container image.",
		Example: `  cosign sign --key <key path>|<kms uri> [--payload <path>] [-a key=value] [--upload=true|false] [-f] [-r] <image uri>

  # sign a container image with Google sign-in (experimental)
  COSIGN_EXPERIMENTAL=1 cosign sign <IMAGE>

  # sign a container image with a local key pair file
  cosign sign --key cosign.key <IMAGE>

  # sign a multi-arch container image AND all referenced, discrete images
  cosign sign --key cosign.key --recursive <MULTI-ARCH IMAGE>

  # sign a container image and add annotations
  cosign sign --key cosign.key -a key1=value1 -a key2=value2 <IMAGE>

  # sign a container image with a key stored in an environment variable
  cosign sign --key env://[ENV_VAR] <IMAGE>

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

  # sign a container image with a key, attaching a certificate and certificate chain
  cosign sign --key cosign.key --cert cosign.crt --cert-chain chain.crt <IMAGE>

  # sign a container in a registry which does not fully support OCI media types
  COSIGN_DOCKER_MEDIA_TYPES=1 cosign sign --key cosign.key legacy-registry.example.com/my/image`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch o.Attachment {
			case "sbom", "":
				break
			default:
				return flag.ErrHelp
			}
			oidcClientSecret, err := o.OIDC.ClientSecret()
			if err != nil {
				return err
			}
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
				OIDCClientSecret:         oidcClientSecret,
				OIDCRedirectURL:          o.OIDC.RedirectURL,
			}
			annotationsMap, err := o.AnnotationsMap()
			if err != nil {
				return err
			}
			if err := sign.SignCmd(ro, ko, o.Registry, annotationsMap.Annotations, args, o.Cert, o.CertChain, o.Upload,
				o.OutputSignature, o.OutputCertificate, o.PayloadPath, o.Force, o.Recursive, o.Attachment); err != nil {
				if o.Attachment == "" {
					return errors.Wrapf(err, "signing %v", args)
				}
				return errors.Wrapf(err, "signing attachment %s for image %v", o.Attachment, args)
			}
			return nil
		},
	}
	o.AddFlags(cmd)
	return cmd
}
