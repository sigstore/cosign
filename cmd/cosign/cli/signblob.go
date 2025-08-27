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
	"github.com/spf13/viper"
)

func SignBlob() *cobra.Command {
	o := &options.SignBlobOptions{}
	viper.RegisterAlias("output", "output-signature")

	cmd := &cobra.Command{
		Use:   "sign-blob",
		Short: "Sign the supplied blob, outputting the base64-encoded signature to stdout.",
		Example: `  cosign sign-blob --key <key path>|<kms uri> <blob>

  # sign a blob with Google sign-in (experimental)
  cosign sign-blob <FILE> --output-signature <FILE> --output-certificate <FILE>

  # sign a blob with a local key pair file
  cosign sign-blob --key cosign.key <FILE>

  # sign a blob with a key stored in an environment variable
  cosign sign-blob --key env://[ENV_VAR] <FILE>

  # sign a blob with a key pair stored in Azure Key Vault
  cosign sign-blob --key azurekms://[VAULT_NAME][VAULT_URI]/[KEY] <FILE>

  # sign a blob with a key pair stored in AWS KMS
  cosign sign-blob --key awskms://[ENDPOINT]/[ID/ALIAS/ARN] <FILE>

  # sign a blob with a key pair stored in Google Cloud KMS
  cosign sign-blob --key gcpkms://projects/[PROJECT]/locations/global/keyRings/[KEYRING]/cryptoKeys/[KEY] <FILE>

  # sign a blob with a key pair stored in Hashicorp Vault
  cosign sign-blob --key hashivault://[KEY] <FILE>`,
		Args:             cobra.MinimumNArgs(1),
		PersistentPreRun: options.BindViper,
		PreRunE: func(_ *cobra.Command, _ []string) error {
			if options.NOf(o.Key, o.SecurityKey.Use) > 1 {
				return &options.KeyParseError{}
			}
			return nil
		},
		RunE: func(_ *cobra.Command, args []string) error {
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
				BundlePath:                     o.BundlePath,
				NewBundleFormat:                o.NewBundleFormat,
				SkipConfirmation:               o.SkipConfirmation,
				TSAClientCACert:                o.TSAClientCACert,
				TSAClientCert:                  o.TSAClientCert,
				TSAClientKey:                   o.TSAClientKey,
				TSAServerName:                  o.TSAServerName,
				TSAServerURL:                   o.TSAServerURL,
				RFC3161TimestampPath:           o.RFC3161TimestampPath,
				IssueCertificateForExistingKey: o.IssueCertificate,
			}
			if (o.Key == "" || o.IssueCertificate) && env.Getenv(env.VariableSigstoreCTLogPublicKeyFile) == "" {
				if o.TrustedRootPath != "" {
					ko.TrustedMaterial, err = root.NewTrustedRootFromPath(o.TrustedRootPath)
					if err != nil {
						return fmt.Errorf("loading trusted root: %w", err)
					}
				} else {
					trustedMaterial, err := cosign.TrustedRoot()
					if err != nil {
						ui.Warnf(context.Background(), "Could not fetch trusted_root.json from the TUF repository. Continuing with individual targets. Error from TUF: %v", err)
					}
					ko.TrustedMaterial = trustedMaterial
				}
			}
			if (o.UseSigningConfig || o.SigningConfigPath != "") && o.BundlePath == "" {
				return fmt.Errorf("must provide --bundle with --signing-config or --use-signing-config")
			}
			if o.UseSigningConfig {
				signingConfig, err := cosign.SigningConfig()
				if err != nil {
					return fmt.Errorf("error getting signing config from TUF: %w", err)
				}
				ko.SigningConfig = signingConfig
			} else if o.SigningConfigPath != "" {
				signingConfig, err := root.NewSigningConfigFromPath(o.SigningConfigPath)
				if err != nil {
					return fmt.Errorf("error reading signing config from file: %w", err)
				}
				ko.SigningConfig = signingConfig
			}

			for _, blob := range args {
				// TODO: remove when the output flag has been deprecated
				if o.Output != "" {
					fmt.Fprintln(os.Stderr, "WARNING: the '--output' flag is deprecated and will be removed in the future. Use '--output-signature'")
					o.OutputSignature = o.Output
				}

				if _, err := sign.SignBlobCmd(ro, ko, blob, o.Base64Output, o.OutputSignature, o.OutputCertificate, o.TlogUpload); err != nil {
					return fmt.Errorf("signing %s: %w", blob, err)
				}
			}
			return nil
		},
	}

	o.AddFlags(cmd)
	return cmd
}
