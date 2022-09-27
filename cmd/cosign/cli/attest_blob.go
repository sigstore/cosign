package cli

import (
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/cmd/cosign/cli/attest"
	"github.com/sigstore/cosign/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/spf13/cobra"
)

func AttestBlob() *cobra.Command {
	o := &options.AttestBlobOptions{}

	cmd := &cobra.Command{
		Use:   "attest-blob",
		Short: "Attest the supplied blob.",
		Example: `  cosign attest-blob --key <key path>|<kms uri> [--predicate <path>] [--a key=value] [--no-upload=true|false] [--f] [--r] <BLOB uri>

  # attach an attestation to a blob Google sign-in (experimental)
  COSIGN_EXPERIMENTAL=1 cosign attest-blob --timeout 90s --predicate <FILE> --type <TYPE> <BLOB>

  # attach an attestation to a blob with a local key pair file
  cosign attest-blob --predicate <FILE> --type <TYPE> --key cosign.key <BLOB>

  # attach an attestation to a blob with a key pair stored in Azure Key Vault
  cosign attest-blob --predicate <FILE> --type <TYPE> --key azurekms://[VAULT_NAME][VAULT_URI]/[KEY] <BLOB>

  # attach an attestation to a blob with a key pair stored in AWS KMS
  cosign attest-blob --predicate <FILE> --type <TYPE> --key awskms://[ENDPOINT]/[ID/ALIAS/ARN] <BLOB>

  # attach an attestation to a blob with a key pair stored in Google Cloud KMS
  cosign attest-blob --predicate <FILE> --type <TYPE> --key gcpkms://projects/[PROJECT]/locations/global/keyRings/[KEYRING]/cryptoKeys/[KEY]/versions/[VERSION] <BLOB>

  # attach an attestation to a blob with a key pair stored in Hashicorp Vault
  cosign attest-blob --predicate <FILE> --type <TYPE> --key hashivault://[KEY] <BLOB>`,

		Args: cobra.MinimumNArgs(1),
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
				InsecureSkipFulcioVerify: o.Fulcio.InsecureSkipFulcioVerify,
				RekorURL:                 o.Rekor.URL,
				OIDCIssuer:               o.OIDC.Issuer,
				OIDCClientID:             o.OIDC.ClientID,
				OIDCClientSecret:         oidcClientSecret,
				OIDCRedirectURL:          o.OIDC.RedirectURL,
			}
			for _, artifact := range args {
				if err := attest.AttestBlobCmd(cmd.Context(), ko, artifact, o.Hash, o.Cert, o.CertChain, o.NoUpload,
					o.Predicate.Path, o.Force, o.Predicate.Type, o.Replace, ro.Timeout); err != nil {
					return errors.Wrapf(err, "attesting %s", artifact)
				}
			}
			return nil
		},
	}
	o.AddFlags(cmd)
	return cmd
}
