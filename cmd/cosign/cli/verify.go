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
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/cmd/cosign/cli/verify"
)

func Verify() *cobra.Command {
	o := &options.VerifyOptions{}

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a signature on the supplied container image",
		Long: `Verify signature and annotations on an image by checking the claims
against the transparency log.`,
		Example: `  cosign verify --key <key path>|<key url>|<kms uri> <image uri> [<image uri> ...]

  # verify cosign claims and signing certificates on the image
  cosign verify <IMAGE>

  # verify multiple images
  cosign verify <IMAGE_1> <IMAGE_2> ...

  # additionally verify specified annotations
  cosign verify -a key1=val1 -a key2=val2 <IMAGE>

  # (experimental) additionally, verify with the transparency log
  COSIGN_EXPERIMENTAL=1 cosign verify <IMAGE>

  # verify image with an on-disk public key
  cosign verify --key cosign.pub <IMAGE>

  # verify image with an on-disk public key, manually specifying the
  # signature digest algorithm
  cosign verify --key cosign.pub --signature-digest-algorithm sha512 <IMAGE>

  # verify image with an on-disk signed image from 'cosign save'
  cosign verify --key cosign.pub --local-image <PATH>

  # verify image with public key provided by URL
  cosign verify --key https://host.for/[FILE] <IMAGE>

  # verify image with public key stored in Google Cloud KMS
  cosign verify --key gcpkms://projects/[PROJECT]/locations/global/keyRings/[KEYRING]/cryptoKeys/[KEY] <IMAGE>

  # verify image with public key stored in Hashicorp Vault
  cosign verify --key hashivault://[KEY] <IMAGE>

  # verify image with public key stored in a Kubernetes secret
  cosign verify --key k8s://[NAMESPACE]/[KEY] <IMAGE>

  # verify image with public key stored in GitLab with project name
  cosign verify --key gitlab://[OWNER]/[PROJECT_NAME] <IMAGE>

  # verify image with public key stored in GitLab with project id
  cosign verify --key gitlab://[PROJECT_ID] <IMAGE>`,

		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			annotations, err := o.AnnotationsMap()
			if err != nil {
				return err
			}

			hashAlgorithm, err := o.SignatureDigest.HashAlgorithm()
			if err != nil {
				return err
			}

			v := verify.VerifyCommand{
				RegistryOptions: o.Registry,
				CheckClaims:     o.CheckClaims,
				KeyRef:          o.Key,
				CertRef:         o.CertVerify.Cert,
				CertEmail:       o.CertVerify.CertEmail,
				Sk:              o.SecurityKey.Use,
				Slot:            o.SecurityKey.Slot,
				Output:          o.Output,
				RekorURL:        o.Rekor.URL,
				Attachment:      o.Attachment,
				Annotations:     annotations,
				HashAlgorithm:   hashAlgorithm,
				SignatureRef:    o.SignatureRef,
				LocalImage:      o.LocalImage,
			}

			return v.Exec(cmd.Context(), args)
		},
	}

	o.AddFlags(cmd)
	return cmd
}

func VerifyAttestation() *cobra.Command {
	o := &options.VerifyAttestationOptions{}

	cmd := &cobra.Command{
		Use:   "verify-attestation",
		Short: "Verify an attestation on the supplied container image",
		Long: `Verify an attestation on an image by checking the claims
against the transparency log.`,
		Example: `  cosign verify-attestation --key <key path>|<key url>|<kms uri> <image uri> [<image uri> ...]

  # verify cosign attestations on the image
  cosign verify-attestation <IMAGE>

  # verify multiple images
  cosign verify-attestation <IMAGE_1> <IMAGE_2> ...

  # additionally verify specified annotations
  cosign verify-attestation -a key1=val1 -a key2=val2 <IMAGE>

  # (experimental) additionally, verify with the transparency log
  COSIGN_EXPERIMENTAL=1 cosign verify-attestation <IMAGE>

  # verify image with public key
  cosign verify-attestation --key cosign.pub <IMAGE>

  # verify image attestations with an on-disk signed image from 'cosign save'
  cosign verify-attestation --key cosign.pub --local-image <PATH>

  # verify image with public key provided by URL
  cosign verify-attestation --key https://host.for/<FILE> <IMAGE>

  # verify image with public key stored in Google Cloud KMS
  cosign verify-attestation --key gcpkms://projects/<PROJECT>/locations/global/keyRings/<KEYRING>/cryptoKeys/<KEY> <IMAGE>

  # verify image with public key stored in Hashicorp Vault
  cosign verify-attestation --key hashivault:///<KEY> <IMAGE>

  # verify image with public key stored in GitLab with project name
  cosign verify-attestation --key gitlab://[OWNER]/[PROJECT_NAME] <IMAGE>

  # verify image with public key stored in GitLab with project id
  cosign verify-attestation --key gitlab://[PROJECT_ID] <IMAGE>`,

		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v := verify.VerifyAttestationCommand{
				RegistryOptions: o.Registry,
				CheckClaims:     o.CheckClaims,
				CertRef:         o.CertVerify.Cert,
				CertEmail:       o.CertVerify.CertEmail,
				KeyRef:          o.Key,
				Sk:              o.SecurityKey.Use,
				Slot:            o.SecurityKey.Slot,
				Output:          o.Output,
				RekorURL:        o.Rekor.URL,
				PredicateType:   o.Predicate.Type,
				Policies:        o.Policies,
				LocalImage:      o.LocalImage,
			}
			return v.Exec(cmd.Context(), args)
		},
	}

	o.AddFlags(cmd)
	return cmd
}

func VerifyBlob() *cobra.Command {
	o := &options.VerifyBlobOptions{}

	cmd := &cobra.Command{
		Use:   "verify-blob",
		Short: "Verify a signature on the supplied blob",
		Long: `Verify a signature on the supplied blob input using the specified key reference.
You may specify either a key, a certificate or a kms reference to verify against.
	If you use a key or a certificate, you must specify the path to them on disk.

The signature may be specified as a path to a file or a base64 encoded string.
The blob may be specified as a path to a file or - for stdin.`,
		Example: `  cosign verify-blob (--key <key path>|<key url>|<kms uri>)|(--cert <cert>) --signature <sig> <blob>

  # Verify a simple blob and message
  cosign verify-blob --key cosign.pub --signature sig msg

  # Verify a simple blob with remote signature URL, both http and https schemes are supported
  cosign verify-blob --key cosign.pub --signature http://host/my.sig

  # Verify a signature from an environment variable
  cosign verify-blob --key cosign.pub --signature $sig msg

  # verify a signature with public key provided by URL
  cosign verify-blob --key https://host.for/<FILE> --signature $sig msg

  # Verify a signature against a payload from another process using process redirection
  cosign verify-blob --key cosign.pub --signature $sig <(git rev-parse HEAD)

  # Verify a signature against Azure Key Vault
  cosign verify-blob --key azurekms://[VAULT_NAME][VAULT_URI]/[KEY] --signature $sig <blob>

  # Verify a signature against AWS KMS
  cosign verify-blob --key awskms://[ENDPOINT]/[ID/ALIAS/ARN] --signature $sig <blob>

  # Verify a signature against Google Cloud KMS
  cosign verify-blob --key gcpkms://projects/[PROJECT ID]/locations/[LOCATION]/keyRings/[KEYRING]/cryptoKeys/[KEY] --signature $sig <blob>

  # Verify a signature against Hashicorp Vault
  cosign verify-blob --key hashivault://[KEY] --signature $sig <blob>

  # Verify a signature against GitLab with project name
  cosign verify-blob --key gitlab://[OWNER]/[PROJECT_NAME]  --signature $sig <blob>

  # Verify a signature against GitLab with project id
  cosign verify-blob --key gitlab://[PROJECT_ID]  --signature $sig <blob>

  # Verify a signature against a certificate
  cosign verify-blob --cert <cert> --signature $sig <blob>
`,

		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ko := sign.KeyOpts{
				KeyRef:     o.Key,
				Sk:         o.SecurityKey.Use,
				Slot:       o.SecurityKey.Slot,
				RekorURL:   o.Rekor.URL,
				BundlePath: o.BundlePath,
			}
			if err := verify.VerifyBlobCmd(cmd.Context(), ko, o.CertVerify.Cert,
				o.CertVerify.CertEmail, o.Signature, args[0]); err != nil {
				return errors.Wrapf(err, "verifying blob %s", args)
			}
			return nil
		},
	}

	o.AddFlags(cmd)
	return cmd
}
