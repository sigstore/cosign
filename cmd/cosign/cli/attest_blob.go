// Copyright 2022 The Sigstore Authors.
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

func AttestBlob() *cobra.Command {
	o := &options.AttestBlobOptions{}

	cmd := &cobra.Command{
		Use:   "attest-blob",
		Short: "Attest the supplied blob",
		Example: `  cosign attest-blob --key <key path>|<kms uri> [--predicate <path>] [--yes] --bundle <bundle.json> <BLOB uri>

  # attach an attestation to a blob with a local key pair file and write the bundle to a file
  cosign attest-blob --predicate <FILE> --type <TYPE> --key cosign.key --bundle <path> <BLOB>

  # attach an attestation to a blob with a key pair stored in Azure Key Vault
  cosign attest-blob --predicate <FILE> --type <TYPE> --key azurekms://[VAULT_NAME][VAULT_URI]/[KEY] --bundle <bundle.json> <BLOB>

  # attach an attestation to a blob with a key pair stored in AWS KMS
  cosign attest-blob --predicate <FILE> --type <TYPE> --key awskms://[ENDPOINT]/[ID/ALIAS/ARN] --bundle <bundle.json> <BLOB>

  # attach an attestation to a blob with a key pair stored in Google Cloud KMS
  cosign attest-blob --predicate <FILE> --type <TYPE> --key gcpkms://projects/[PROJECT]/locations/global/keyRings/[KEYRING]/cryptoKeys/[KEY]/versions/[VERSION] --bundle <bundle.json> <BLOB>

  # attach an attestation to a blob with a key pair stored in Hashicorp Vault
  cosign attest-blob --predicate <FILE> --type <TYPE> --key hashivault://[KEY] --bundle <bundle.json> <BLOB>

  # supply attestation via stdin
  echo <PAYLOAD> | cosign attest-blob --predicate - --bundle <bundle.json> --yes`,

		PersistentPreRun: options.BindViper,
		PreRunE: func(_ *cobra.Command, _ []string) error {
			if o.BundlePath == "" {
				return fmt.Errorf("must specify --bundle")
			}
			if (o.Key == "" && !o.SecurityKey.Use) || o.IssueCertificate {
				if !o.UseSigningConfig && o.SigningConfigPath == "" {
					return fmt.Errorf("keyless or certificate-based attesting requires a signing config (either from TUF via --use-signing-config or explicitly via a file with --signing-config)")
				}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if o.Predicate.Statement == "" && len(args) != 1 {
				return cobra.ExactArgs(1)(cmd, args)
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

			v := attest.AttestBlobCommand{
				KeyOpts:       ko,
				CertPath:      o.Cert,
				CertChainPath: o.CertChain,
				ArtifactHash:  o.Hash,
				PredicateType: o.Predicate.Type,
				PredicatePath: o.Predicate.Path,
				StatementPath: o.Predicate.Statement,
				Timeout:       ro.Timeout,
			}
			var artifactPath string
			if len(args) == 1 {
				artifactPath = args[0]
			}
			return v.Exec(cmd.Context(), artifactPath)
		},
	}
	o.AddFlags(cmd)
	return cmd
}
