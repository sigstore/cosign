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
		Example: `  cosign attest-blob --key <key path>|<kms uri> [--predicate <path>] [--a key=value] [--f] [--r] <BLOB uri>

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
			ko := options.KeyOpts{
				KeyRef:   o.Key,
				PassFunc: generate.GetPass,
				Sk:       o.SecurityKey.Use,
				Slot:     o.SecurityKey.Slot,
			}
			for _, artifact := range args {
				if err := attest.AttestBlobCmd(cmd.Context(), ko, artifact, o.Hash, o.Cert, o.CertChain,
					o.Predicate.Path, o.Predicate.Type, ro.Timeout, o.OutputSignature); err != nil {
					return errors.Wrapf(err, "attesting %s", artifact)
				}
			}
			return nil
		},
	}
	o.AddFlags(cmd)
	return cmd
}
