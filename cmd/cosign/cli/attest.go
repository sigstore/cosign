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

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/attest"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/internal/ui"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/env"
	"github.com/spf13/cobra"
)

func Attest() *cobra.Command {
	o := &options.AttestOptions{}

	cmd := &cobra.Command{
		Use:   "attest",
		Short: "Attest the supplied container image.",
		Example: `  cosign attest --key <key path>|<kms uri> [--predicate <path>] [--a key=value] [--no-upload=true|false] [--record-creation-timestamp=true|false] [--f] [--r] <image uri>

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
  cosign attest --predicate <FILE> --type <TYPE> --key cosign.key --no-upload true <IMAGE>

  # attach an attestation to a container image and honor the creation timestamp of the signature
  cosign attest --predicate <FILE> --type <TYPE> --key cosign.key --record-creation-timestamp <IMAGE>`,

		Args:             cobra.MinimumNArgs(1),
		PersistentPreRun: options.BindViper,
		RunE: func(cmd *cobra.Command, args []string) error {
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
				NewBundleFormat:          o.NewBundleFormat,
			}
			if o.Key == "" && env.Getenv(env.VariableSigstoreCTLogPublicKeyFile) == "" { // Get the trusted root if using fulcio for signing
				trustedMaterial, err := cosign.TrustedRoot()
				if err != nil {
					ui.Warnf(context.Background(), "Could not fetch trusted_root.json from the TUF repository. Continuing with individual targets. Error from TUF: %v", err)
				}
				ko.TrustedMaterial = trustedMaterial
			}
			// TODO(#4324): Add support for SigningConfig
			attestCommand := attest.AttestCommand{
				KeyOpts:                 ko,
				RegistryOptions:         o.Registry,
				CertPath:                o.Cert,
				CertChainPath:           o.CertChain,
				NoUpload:                o.NoUpload,
				PredicatePath:           o.Predicate.Path,
				PredicateType:           o.Predicate.Type,
				Replace:                 o.Replace,
				Timeout:                 ro.Timeout,
				TlogUpload:              o.TlogUpload,
				RekorEntryType:          o.RekorEntryType,
				RecordCreationTimestamp: o.RecordCreationTimestamp,
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
