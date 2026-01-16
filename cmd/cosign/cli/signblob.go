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
	"fmt"
	"os"
	"strings"

	"github.com/sigstore/cosign/v3/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/signcommon"
	"github.com/sigstore/cosign/v3/pkg/cosign"
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

			// Check if the algorithm is in the list of supported algorithms
			supportedAlgorithms := cosign.GetSupportedAlgorithms()
			isValid := false
			for _, algo := range supportedAlgorithms {
				if algo == o.SigningAlgorithm {
					isValid = true
					break
				}
			}
			if !isValid {
				return fmt.Errorf("invalid signing algorithm: %s. Supported algorithms are: %s",
					o.SigningAlgorithm, strings.Join(supportedAlgorithms, ", "))
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
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
				RekorVersion:                   o.Rekor.Version,
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
				SigningAlgorithm:               o.SigningAlgorithm,
			}
			if err := signcommon.LoadTrustedMaterialAndSigningConfig(cmd.Context(), &ko, o.UseSigningConfig, o.SigningConfigPath,
				o.Rekor.URL, o.Fulcio.URL, o.OIDC.Issuer, o.TSAServerURL, o.TrustedRootPath, o.TlogUpload,
				o.NewBundleFormat, o.BundlePath, o.Key, o.IssueCertificate,
				o.Output, "", o.OutputCertificate, "", o.OutputSignature); err != nil {
				return err
			}

			for _, blob := range args {
				// TODO: remove when the output flag has been deprecated
				if o.Output != "" {
					fmt.Fprintln(os.Stderr, "WARNING: the '--output' flag is deprecated and will be removed in the future. Use '--output-signature'")
					o.OutputSignature = o.Output
				}

				if _, err := sign.SignBlobCmd(cmd.Context(), ro, ko, blob, o.Cert, o.CertChain, o.Base64Output, o.OutputSignature, o.OutputCertificate, o.TlogUpload); err != nil {
					return fmt.Errorf("signing %s: %w", blob, err)
				}
			}
			return nil
		},
	}

	o.AddFlags(cmd)
	return cmd
}
