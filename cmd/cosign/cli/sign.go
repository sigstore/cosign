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
	"context"
	"fmt"
	"os"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/v2/internal/ui"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/env"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/spf13/cobra"
)

func Sign() *cobra.Command {
	o := &options.SignOptions{}

	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign the supplied container image.",
		Long: `Sign the supplied container image.

Make sure to sign the image by its digest (@sha256:...) rather than by tag
(:latest) so that you actually sign what you think you're signing! This prevents
race conditions or (worse) malicious tampering.
`,
		Example: `  cosign sign --key <key path>|<kms uri> [--payload <path>] [-a key=value] [--upload=true|false] [-f] [-r] <image digest uri>

  # sign a container image with the Sigstore OIDC flow
  cosign sign <IMAGE DIGEST>

  # sign a container image with a local key pair file
  cosign sign --key cosign.key <IMAGE DIGEST>

  # sign a multi-arch container image AND all referenced, discrete images
  cosign sign --key cosign.key --recursive <MULTI-ARCH IMAGE DIGEST>

  # sign a container image and add annotations
  cosign sign --key cosign.key -a key1=value1 -a key2=value2 <IMAGE DIGEST>

  # sign a container image with a key stored in an environment variable
  cosign sign --key env://[ENV_VAR] <IMAGE DIGEST>

  # sign a container image with a key pair stored in Azure Key Vault
  cosign sign --key azurekms://[VAULT_NAME][VAULT_URI]/[KEY] <IMAGE DIGEST>

  # sign a container image with a key pair stored in AWS KMS
  cosign sign --key awskms://[ENDPOINT]/[ID/ALIAS/ARN] <IMAGE DIGEST>

  # sign a container image with a key pair stored in Google Cloud KMS
  cosign sign --key gcpkms://projects/[PROJECT]/locations/global/keyRings/[KEYRING]/cryptoKeys/[KEY]/versions/[VERSION] <IMAGE DIGEST>

  # sign a container image with a key pair stored in Hashicorp Vault
  cosign sign --key hashivault://[KEY] <IMAGE DIGEST>

  # sign a container image with a key pair stored in a Kubernetes secret
  cosign sign --key k8s://[NAMESPACE]/[KEY] <IMAGE DIGEST>

  # sign a container image with a key, attaching a certificate and certificate chain
  cosign sign --key cosign.key --cert cosign.crt --cert-chain chain.crt <IMAGE DIGEST>

  # sign a container in a registry which does not fully support OCI media types
  COSIGN_DOCKER_MEDIA_TYPES=1 cosign sign --key cosign.key legacy-registry.example.com/my/image@<DIGEST>

  # sign a container image and upload to the transparency log
  cosign sign --key cosign.key <IMAGE DIGEST>

  # sign a container image and skip uploading to the transparency log
  cosign sign --key cosign.key --tlog-upload=false <IMAGE DIGEST>

  # sign a container image by manually setting the container image identity
  cosign sign --sign-container-identity <NEW IMAGE DIGEST> <IMAGE DIGEST>

  # sign a container image and honor the creation timestamp of the signature
  cosign sign --key cosign.key --record-creation-timestamp <IMAGE DIGEST>`,

		Args:             cobra.MinimumNArgs(1),
		PersistentPreRun: options.BindViper,
		RunE: func(_ *cobra.Command, args []string) error {
			switch o.Attachment {
			case "sbom":
				fmt.Fprintln(os.Stderr, options.SBOMAttachmentDeprecation)
			case "":
				break
			default:
				return fmt.Errorf("specified image attachment %s not specified. Can be 'sbom'", o.Attachment)
			}
			oidcClientSecret, err := o.OIDC.ClientSecret()
			if err != nil {
				return err
			}

			ko := options.KeyOpts{
				KeyRef:                         o.Key,
				PassFunc:                       generate.GetPass,
				Sk:                             o.SecurityKey.Use,
				Slot:                           o.SecurityKey.Slot,
				FulcioURL:                      o.Fulcio.URL,
				IDToken:                        o.Fulcio.IdentityToken,
				FulcioAuthFlow:                 o.Fulcio.AuthFlow,
				InsecureSkipFulcioVerify:       o.Fulcio.InsecureSkipFulcioVerify,
				RekorURL:                       o.Rekor.URL,
				OIDCIssuer:                     o.OIDC.Issuer,
				OIDCClientID:                   o.OIDC.ClientID,
				OIDCClientSecret:               oidcClientSecret,
				OIDCRedirectURL:                o.OIDC.RedirectURL,
				OIDCDisableProviders:           o.OIDC.DisableAmbientProviders,
				OIDCProvider:                   o.OIDC.Provider,
				SkipConfirmation:               o.SkipConfirmation,
				TSAClientCACert:                o.TSAClientCACert,
				TSAClientCert:                  o.TSAClientCert,
				TSAClientKey:                   o.TSAClientKey,
				TSAServerName:                  o.TSAServerName,
				TSAServerURL:                   o.TSAServerURL,
				IssueCertificateForExistingKey: o.IssueCertificate,
			}
			// If a signing config is used, then service URLs cannot be specified
			if (o.UseSigningConfig || o.SigningConfigPath != "") &&
				((o.Rekor.URL != "" && o.Rekor.URL != options.DefaultRekorURL) ||
					(o.Fulcio.URL != "" && o.Fulcio.URL != options.DefaultFulcioURL) ||
					(o.OIDC.Issuer != "" && o.OIDC.Issuer != options.DefaultOIDCIssuerURL) ||
					o.TSAServerURL != "") {
				return fmt.Errorf("cannot specify service URLs and use signing config")
			}
			// Signing config requires a bundle as output for verification materials since sigstore-go is used
			if (o.UseSigningConfig || o.SigningConfigPath != "") && !o.NewBundleFormat {
				return fmt.Errorf("must provide --new-bundle-format with --signing-config or --use-signing-config")
			}
			// Fetch a trusted root when:
			// * requesting a certificate and no CT log key is provided to verify an SCT
			// * using a signing config and signing using sigstore-go
			if ((o.Key == "" || o.IssueCertificate) && env.Getenv(env.VariableSigstoreCTLogPublicKeyFile) == "") ||
				(o.UseSigningConfig || o.SigningConfigPath != "") {
				if o.TrustedRootPath != "" {
					ko.TrustedMaterial, err = root.NewTrustedRootFromPath(o.TrustedRootPath)
					if err != nil {
						return fmt.Errorf("loading trusted root: %w", err)
					}
				} else {
					ko.TrustedMaterial, err = cosign.TrustedRoot()
					if err != nil {
						ui.Warnf(context.Background(), "Could not fetch trusted_root.json from the TUF repository. Continuing with individual targets. Error from TUF: %v", err)
					}
				}
			}
			if o.UseSigningConfig {
				ko.SigningConfig, err = cosign.SigningConfig()
				if err != nil {
					return fmt.Errorf("error getting signing config from TUF: %w", err)
				}
			} else if o.SigningConfigPath != "" {
				ko.SigningConfig, err = root.NewSigningConfigFromPath(o.SigningConfigPath)
				if err != nil {
					return fmt.Errorf("error reading signing config from file: %w", err)
				}
			}

			if err := sign.SignCmd(ro, ko, *o, args); err != nil {
				if o.Attachment == "" {
					return fmt.Errorf("signing %v: %w", args, err)
				}
				return fmt.Errorf("signing attachment %s for image %v: %w", o.Attachment, args, err)
			}
			return nil
		},
	}
	o.AddFlags(cmd)
	return cmd
}
