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

	"github.com/sigstore/cosign/v3/cmd/cosign/cli/attest"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/signcommon"
	"github.com/spf13/cobra"
)

func Attest() *cobra.Command {
	o := &options.AttestOptions{}

	cmd := &cobra.Command{
		Use:   "attest",
		Short: "Attest the supplied container image",
		Example: `  cosign attest --key <key path>|<kms uri> [--predicate <path>] [--no-upload=true|false] [--yes] <image uri>

  # attach an attestation to a container image Google sign-in
  cosign attest --timeout 90s --predicate <FILE> --type <TYPE> <IMAGE>

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

  # attach an attestation to a container image with a local key pair file, including a certificate and certificate chain
  cosign attest --predicate <FILE> --type <TYPE> --key cosign.key --cert cosign.crt --cert-chain chain.crt <IMAGE>

  # attach an attestation to a container image which does not fully support OCI media types
  COSIGN_DOCKER_MEDIA_TYPES=1 cosign attest --predicate <FILE> --type <TYPE> --key cosign.key legacy-registry.example.com/my/image

  # supply attestation via stdin
  echo <PAYLOAD> | cosign attest --predicate - <IMAGE>

  # write attestation to stdout
  cosign attest --predicate <FILE> --type <TYPE> --key cosign.key --no-upload true <IMAGE>`,

		Args:             cobra.MinimumNArgs(1),
		PersistentPreRun: options.BindViper,
		PreRunE: func(_ *cobra.Command, _ []string) error {
			if o.NoUpload && o.BundlePath == "" {
				return fmt.Errorf("must enable upload to the OCI registry or specify a local --bundle path")
			}
			var attestType string
			if o.Key == "" && !o.SecurityKey.Use {
				attestType = "keyless"
			} else if o.IssueCertificate {
				attestType = "certificate-based"
			}
			if attestType != "" {
				if !o.UseSigningConfig && o.SigningConfigPath == "" {
					return fmt.Errorf("%s attesting requires a signing config (either from TUF via --use-signing-config or explicitly via a file with --signing-config)", attestType)
				}
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
				IDToken:                        o.Fulcio.IdentityToken,
				FulcioAuthFlow:                 o.Fulcio.AuthFlow,
				OIDCClientID:                   o.OIDC.ClientID,
				OIDCClientSecret:               oidcClientSecret,
				OIDCRedirectURL:                o.OIDC.RedirectURL,
				OIDCDisableProviders:           o.OIDC.DisableAmbientProviders,
				OIDCProvider:                   o.OIDC.Provider,
				SkipConfirmation:               o.SkipConfirmation,
				TSAClientCACert:                o.TSAClientCACert,
				TSAClientKey:                   o.TSAClientKey,
				TSAClientCert:                  o.TSAClientCert,
				TSAServerName:                  o.TSAServerName,
				IssueCertificateForExistingKey: o.IssueCertificate,
				BundlePath:                     o.BundlePath,
			}
			if err := signcommon.LoadTrustedMaterialAndSigningConfig(cmd.Context(), &ko, o.UseSigningConfig, o.SigningConfigPath,
				o.TrustedRootPath, o.Key); err != nil {
				return err
			}

			attestCommand := attest.AttestCommand{
				KeyOpts:         ko,
				RegistryOptions: o.Registry,
				CertPath:        o.Cert,
				CertChainPath:   o.CertChain,
				NoUpload:        o.NoUpload,
				PredicatePath:   o.Predicate.Path,
				PredicateType:   o.Predicate.Type,
				Timeout:         ro.Timeout,
			}

			for _, img := range args {
				if err := attestCommand.Exec(cmd.Context(), img); err != nil {
					return fmt.Errorf("signing %s: %w", img, err)
				}
			}
			return nil
		},
	}
	o.AddFlags(cmd)
	return cmd
}
