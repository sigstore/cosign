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
	"context"
	"fmt"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/attest"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/internal/ui"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/env"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/spf13/cobra"
)

func AttestBlob() *cobra.Command {
	o := &options.AttestBlobOptions{}

	cmd := &cobra.Command{
		Use:   "attest-blob",
		Short: "Attest the supplied blob.",
		Example: `  cosign attest-blob --key <key path>|<kms uri> [--predicate <path>] [--a key=value] [--f] [--r] <BLOB uri>

  # attach an attestation to a blob with a local key pair file and print the attestation
  cosign attest-blob --predicate <FILE> --type <TYPE> --key cosign.key --output-attestation <path> <BLOB>

  # attach an attestation to a blob with a key pair stored in Azure Key Vault
  cosign attest-blob --predicate <FILE> --type <TYPE> --key azurekms://[VAULT_NAME][VAULT_URI]/[KEY] <BLOB>

  # attach an attestation to a blob with a key pair stored in AWS KMS
  cosign attest-blob --predicate <FILE> --type <TYPE> --key awskms://[ENDPOINT]/[ID/ALIAS/ARN] <BLOB>

  # attach an attestation to a blob with a key pair stored in Google Cloud KMS
  cosign attest-blob --predicate <FILE> --type <TYPE> --key gcpkms://projects/[PROJECT]/locations/global/keyRings/[KEYRING]/cryptoKeys/[KEY]/versions/[VERSION] <BLOB>

  # attach an attestation to a blob with a key pair stored in Hashicorp Vault
  cosign attest-blob --predicate <FILE> --type <TYPE> --key hashivault://[KEY] <BLOB>

  # supply attestation via stdin
  echo <PAYLOAD> | cosign attest-blob --predicate - --yes`,

		PersistentPreRun: options.BindViper,
		RunE: func(cmd *cobra.Command, args []string) error {
			if o.Predicate.Statement == "" && len(args) != 1 {
				return cobra.ExactArgs(1)(cmd, args)
			}
			oidcClientSecret, err := o.OIDC.ClientSecret()
			if err != nil {
				return err
			}

			ko := options.KeyOpts{
				KeyRef:                   o.Key,
				PassFunc:                 generate.GetPass,
				Sk:                       o.SecurityKey.Use,
				Slot:                     o.SecurityKey.Slot,
				FulcioURL:                o.Fulcio.URL,
				IDToken:                  o.Fulcio.IdentityToken,
				FulcioAuthFlow:           o.Fulcio.AuthFlow,
				InsecureSkipFulcioVerify: o.Fulcio.InsecureSkipFulcioVerify,
				RekorURL:                 o.Rekor.URL,
				OIDCIssuer:               o.OIDC.Issuer,
				OIDCClientID:             o.OIDC.ClientID,
				OIDCClientSecret:         oidcClientSecret,
				OIDCRedirectURL:          o.OIDC.RedirectURL,
				OIDCProvider:             o.OIDC.Provider,
				SkipConfirmation:         o.SkipConfirmation,
				TSAClientCACert:          o.TSAClientCACert,
				TSAClientKey:             o.TSAClientKey,
				TSAClientCert:            o.TSAClientCert,
				TSAServerName:            o.TSAServerName,
				TSAServerURL:             o.TSAServerURL,
				RFC3161TimestampPath:     o.RFC3161TimestampPath,
				BundlePath:               o.BundlePath,
				NewBundleFormat:          o.NewBundleFormat,
			}
			if o.Key == "" && env.Getenv(env.VariableSigstoreCTLogPublicKeyFile) == "" { // Get the trusted root if using fulcio for signing
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

			v := attest.AttestBlobCommand{
				KeyOpts:           ko,
				CertPath:          o.Cert,
				CertChainPath:     o.CertChain,
				ArtifactHash:      o.Hash,
				TlogUpload:        o.TlogUpload,
				PredicateType:     o.Predicate.Type,
				PredicatePath:     o.Predicate.Path,
				StatementPath:     o.Predicate.Statement,
				OutputSignature:   o.OutputSignature,
				OutputAttestation: o.OutputAttestation,
				OutputCertificate: o.OutputCertificate,
				Timeout:           ro.Timeout,
				RekorEntryType:    o.RekorEntryType,
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
