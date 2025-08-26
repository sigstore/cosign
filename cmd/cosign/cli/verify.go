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

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/verify"
	"github.com/sigstore/cosign/v2/internal/ui"
	"github.com/spf13/cobra"
)

const ignoreTLogMessage = "Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the %s."

func Verify() *cobra.Command {
	o := &options.VerifyOptions{}

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a signature on the supplied container image",
		Long: `Verify signature and annotations on an image by checking the claims
against the transparency log.`,
		Example: `  cosign verify --key <key path>|<key url>|<kms uri> <image uri> [<image uri> ...]

  # verify cosign claims and signing certificates on the image with the transparency log
  cosign verify <IMAGE>

  # verify multiple images
  cosign verify <IMAGE_1> <IMAGE_2> ...

  # additionally verify specified annotations
  cosign verify -a key1=val1 -a key2=val2 <IMAGE>

  # verify image with an on-disk public key
  cosign verify --key cosign.pub <IMAGE>

  # verify image with an on-disk public key, manually specifying the
  # signature digest algorithm
  cosign verify --key cosign.pub --signature-digest-algorithm sha512 <IMAGE>

  # verify image with an on-disk signed image from 'cosign save'
  cosign verify --key cosign.pub --local-image <PATH>

  # verify image with local certificate and certificate chain
  cosign verify --cert cosign.crt --cert-chain chain.crt <IMAGE>

  # verify image with local certificate and certificate bundles of CA roots
  # and (optionally) CA intermediates
  cosign verify --cert cosign.crt --ca-roots ca-roots.pem --ca-intermediates ca-intermediates.pem <IMAGE>

  # verify image using keyless verification with the given certificate
  # chain and identity parameters, without Fulcio roots (for BYO PKI):
  cosign verify --cert-chain chain.crt --certificate-oidc-issuer https://issuer.example.com --certificate-identity foo@example.com <IMAGE>

  # verify image with public key provided by URL
  cosign verify --key https://host.for/[FILE] <IMAGE>

  # verify image with a key stored in an environment variable
  cosign verify --key env://[ENV_VAR] <IMAGE>

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

		Args:             cobra.MinimumNArgs(1),
		PersistentPreRun: options.BindViper,
		RunE: func(cmd *cobra.Command, args []string) error {
			if o.CommonVerifyOptions.PrivateInfrastructure {
				o.CommonVerifyOptions.IgnoreTlog = true
			}

			annotations, err := o.AnnotationsMap()
			if err != nil {
				return err
			}

			hashAlgorithm, err := o.SignatureDigest.HashAlgorithm()
			if err != nil {
				return err
			}

			v := &verify.VerifyCommand{
				RegistryOptions:              o.Registry,
				CertVerifyOptions:            o.CertVerify,
				CommonVerifyOptions:          o.CommonVerifyOptions,
				CheckClaims:                  o.CheckClaims,
				KeyRef:                       o.Key,
				CertRef:                      o.CertVerify.Cert,
				CertChain:                    o.CertVerify.CertChain,
				CAIntermediates:              o.CertVerify.CAIntermediates,
				CARoots:                      o.CertVerify.CARoots,
				CertGithubWorkflowTrigger:    o.CertVerify.CertGithubWorkflowTrigger,
				CertGithubWorkflowSha:        o.CertVerify.CertGithubWorkflowSha,
				CertGithubWorkflowName:       o.CertVerify.CertGithubWorkflowName,
				CertGithubWorkflowRepository: o.CertVerify.CertGithubWorkflowRepository,
				CertGithubWorkflowRef:        o.CertVerify.CertGithubWorkflowRef,
				IgnoreSCT:                    o.CertVerify.IgnoreSCT,
				SCTRef:                       o.CertVerify.SCT,
				Sk:                           o.SecurityKey.Use,
				Slot:                         o.SecurityKey.Slot,
				Output:                       o.Output,
				RekorURL:                     o.Rekor.URL,
				Attachment:                   o.Attachment,
				Annotations:                  annotations,
				HashAlgorithm:                hashAlgorithm,
				SignatureRef:                 o.SignatureRef,
				PayloadRef:                   o.PayloadRef,
				LocalImage:                   o.LocalImage,
				Offline:                      o.CommonVerifyOptions.Offline,
				TSACertChainPath:             o.CommonVerifyOptions.TSACertChainPath,
				IgnoreTlog:                   o.CommonVerifyOptions.IgnoreTlog,
				MaxWorkers:                   o.CommonVerifyOptions.MaxWorkers,
				ExperimentalOCI11:            o.CommonVerifyOptions.ExperimentalOCI11,
				UseSignedTimestamps:          o.CommonVerifyOptions.UseSignedTimestamps,
				NewBundleFormat:              o.CommonVerifyOptions.NewBundleFormat,
			}

			if o.CommonVerifyOptions.MaxWorkers == 0 {
				return fmt.Errorf("please set the --max-worker flag to a value that is greater than 0")
			}

			if o.Registry.AllowInsecure {
				v.NameOptions = append(v.NameOptions, name.Insecure)
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), ro.Timeout)
			defer cancel()

			if o.CommonVerifyOptions.IgnoreTlog && !o.CommonVerifyOptions.PrivateInfrastructure {
				ui.Warnf(ctx, ignoreTLogMessage, "signature")
			}

			return v.Exec(ctx, args)
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

  # verify cosign attestations on the image against the transparency log
  cosign verify-attestation <IMAGE>

  # verify multiple images
  cosign verify-attestation <IMAGE_1> <IMAGE_2> ...

  # additionally verify specified annotations
  cosign verify-attestation -a key1=val1 -a key2=val2 <IMAGE>

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
  cosign verify-attestation --key gitlab://[PROJECT_ID] <IMAGE>

  # verify image with public key and validate attestation based on Rego policy
  cosign verify-attestation --key cosign.pub --type <PREDICATE_TYPE> --policy <REGO_POLICY> <IMAGE>

  # verify image with public key and validate attestation based on CUE policy
  cosign verify-attestation --key cosign.pub --type <PREDICATE_TYPE> --policy <CUE_POLICY> <IMAGE>`,

		Args:             cobra.MinimumNArgs(1),
		PersistentPreRun: options.BindViper,
		RunE: func(cmd *cobra.Command, args []string) error {
			if o.CommonVerifyOptions.PrivateInfrastructure {
				o.CommonVerifyOptions.IgnoreTlog = true
			}

			v := &verify.VerifyAttestationCommand{
				RegistryOptions:              o.Registry,
				CommonVerifyOptions:          o.CommonVerifyOptions,
				CheckClaims:                  o.CheckClaims,
				CertVerifyOptions:            o.CertVerify,
				CertRef:                      o.CertVerify.Cert,
				CertChain:                    o.CertVerify.CertChain,
				CAIntermediates:              o.CertVerify.CAIntermediates,
				CARoots:                      o.CertVerify.CARoots,
				CertGithubWorkflowTrigger:    o.CertVerify.CertGithubWorkflowTrigger,
				CertGithubWorkflowSha:        o.CertVerify.CertGithubWorkflowSha,
				CertGithubWorkflowName:       o.CertVerify.CertGithubWorkflowName,
				CertGithubWorkflowRepository: o.CertVerify.CertGithubWorkflowRepository,
				CertGithubWorkflowRef:        o.CertVerify.CertGithubWorkflowRef,
				IgnoreSCT:                    o.CertVerify.IgnoreSCT,
				SCTRef:                       o.CertVerify.SCT,
				KeyRef:                       o.Key,
				Sk:                           o.SecurityKey.Use,
				Slot:                         o.SecurityKey.Slot,
				Output:                       o.Output,
				RekorURL:                     o.Rekor.URL,
				PredicateType:                o.Predicate.Type,
				Policies:                     o.Policies,
				LocalImage:                   o.LocalImage,
				NameOptions:                  o.Registry.NameOptions(),
				Offline:                      o.CommonVerifyOptions.Offline,
				TSACertChainPath:             o.CommonVerifyOptions.TSACertChainPath,
				IgnoreTlog:                   o.CommonVerifyOptions.IgnoreTlog,
				MaxWorkers:                   o.CommonVerifyOptions.MaxWorkers,
				UseSignedTimestamps:          o.CommonVerifyOptions.UseSignedTimestamps,
			}

			if o.CommonVerifyOptions.MaxWorkers == 0 {
				return fmt.Errorf("please set the --max-worker flag to a value that is greater than 0")
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), ro.Timeout)
			defer cancel()

			if o.CommonVerifyOptions.IgnoreTlog && !o.CommonVerifyOptions.PrivateInfrastructure {
				ui.Warnf(ctx, ignoreTLogMessage, "attestation")
			}

			return v.Exec(ctx, args)
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
		Example: ` cosign verify-blob (--key <key path>|<key url>|<kms uri>)|(--certificate <cert>) --signature <sig> <blob>

  # Verify a simple blob and message
  cosign verify-blob --key cosign.pub (--signature <sig path>|<sig url> msg)

  # Verify a signature with certificate and CA certificate chain
  cosign verify-blob --certificate cert.pem --certificate-chain certchain.pem --signature $sig <blob>

  # Verify a signature with CA roots and optional intermediate certificates
  cosign verify-blob --certificate cert.pem --ca-roots caroots.pem [--ca-intermediates caintermediates.pem] --signature $sig <blob>

  # Verify a signature from an environment variable
  cosign verify-blob --key cosign.pub --signature $sig msg

  # verify a signature with public key provided by URL
  cosign verify-blob --key https://host.for/<FILE> --signature $sig msg

  # verify a signature with signature and key provided by URL
  cosign verify-blob --key https://host.for/<FILE> --signature https://example.com/<SIG>

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
  cosign verify-blob --certificate <cert> --signature $sig <blob>
`,

		Args:             cobra.ExactArgs(1),
		PersistentPreRun: options.BindViper,
		RunE: func(cmd *cobra.Command, args []string) error {
			if o.CommonVerifyOptions.PrivateInfrastructure {
				o.CommonVerifyOptions.IgnoreTlog = true
			}

			ko := options.KeyOpts{
				KeyRef:               o.Key,
				Sk:                   o.SecurityKey.Use,
				Slot:                 o.SecurityKey.Slot,
				RekorURL:             o.Rekor.URL,
				BundlePath:           o.BundlePath,
				RFC3161TimestampPath: o.RFC3161TimestampPath,
				TSACertChainPath:     o.CommonVerifyOptions.TSACertChainPath,
				NewBundleFormat:      o.CommonVerifyOptions.NewBundleFormat,
			}
			verifyBlobCmd := &verify.VerifyBlobCmd{
				KeyOpts:                      ko,
				CertVerifyOptions:            o.CertVerify,
				CertRef:                      o.CertVerify.Cert,
				CertChain:                    o.CertVerify.CertChain,
				CARoots:                      o.CertVerify.CARoots,
				CAIntermediates:              o.CertVerify.CAIntermediates,
				SigRef:                       o.Signature,
				CertGithubWorkflowTrigger:    o.CertVerify.CertGithubWorkflowTrigger,
				CertGithubWorkflowSHA:        o.CertVerify.CertGithubWorkflowSha,
				CertGithubWorkflowName:       o.CertVerify.CertGithubWorkflowName,
				CertGithubWorkflowRepository: o.CertVerify.CertGithubWorkflowRepository,
				CertGithubWorkflowRef:        o.CertVerify.CertGithubWorkflowRef,
				IgnoreSCT:                    o.CertVerify.IgnoreSCT,
				SCTRef:                       o.CertVerify.SCT,
				Offline:                      o.CommonVerifyOptions.Offline,
				IgnoreTlog:                   o.CommonVerifyOptions.IgnoreTlog,
				UseSignedTimestamps:          o.CommonVerifyOptions.UseSignedTimestamps,
				TrustedRootPath:              o.CommonVerifyOptions.TrustedRootPath,
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), ro.Timeout)
			defer cancel()

			if o.CommonVerifyOptions.IgnoreTlog && !o.CommonVerifyOptions.PrivateInfrastructure {
				ui.Warnf(ctx, ignoreTLogMessage, "blob")
			}

			return verifyBlobCmd.Exec(ctx, args[0])
		},
	}

	o.AddFlags(cmd)
	return cmd
}

func VerifyBlobAttestation() *cobra.Command {
	o := &options.VerifyBlobAttestationOptions{}

	cmd := &cobra.Command{
		Use:   "verify-blob-attestation",
		Short: "Verify an attestation on the supplied blob",
		Long: `Verify an attestation on the supplied blob input using the specified key reference.
You may specify either a key or a kms reference to verify against.

The signature may be specified as a path to a file or a base64 encoded string.
The blob may be specified as a path to a file.`,
		Example: ` cosign verify-blob-attestation (--key <key path>|<key url>|<kms uri>) --signature <sig> [path to BLOB]

  # Verify a simple blob attestation with a DSSE style signature
  cosign verify-blob-attestation --key cosign.pub (--signature <sig path>|<sig url>)[path to BLOB]

`,

		Args:             cobra.MaximumNArgs(1),
		PersistentPreRun: options.BindViper,
		RunE: func(cmd *cobra.Command, args []string) error {
			if o.CommonVerifyOptions.PrivateInfrastructure {
				o.CommonVerifyOptions.IgnoreTlog = true
			}

			ko := options.KeyOpts{
				KeyRef:               o.Key,
				Sk:                   o.SecurityKey.Use,
				Slot:                 o.SecurityKey.Slot,
				RekorURL:             o.Rekor.URL,
				BundlePath:           o.BundlePath,
				RFC3161TimestampPath: o.RFC3161TimestampPath,
				TSACertChainPath:     o.CommonVerifyOptions.TSACertChainPath,
				NewBundleFormat:      o.CommonVerifyOptions.NewBundleFormat,
			}
			v := verify.VerifyBlobAttestationCommand{
				KeyOpts:                      ko,
				PredicateType:                o.Type,
				CheckClaims:                  o.CheckClaims,
				SignaturePath:                o.SignaturePath,
				CertVerifyOptions:            o.CertVerify,
				CertRef:                      o.CertVerify.Cert,
				CertChain:                    o.CertVerify.CertChain,
				CARoots:                      o.CertVerify.CARoots,
				CAIntermediates:              o.CertVerify.CAIntermediates,
				CertGithubWorkflowTrigger:    o.CertVerify.CertGithubWorkflowTrigger,
				CertGithubWorkflowSHA:        o.CertVerify.CertGithubWorkflowSha,
				CertGithubWorkflowName:       o.CertVerify.CertGithubWorkflowName,
				CertGithubWorkflowRepository: o.CertVerify.CertGithubWorkflowRepository,
				CertGithubWorkflowRef:        o.CertVerify.CertGithubWorkflowRef,
				IgnoreSCT:                    o.CertVerify.IgnoreSCT,
				SCTRef:                       o.CertVerify.SCT,
				Offline:                      o.CommonVerifyOptions.Offline,
				IgnoreTlog:                   o.CommonVerifyOptions.IgnoreTlog,
				UseSignedTimestamps:          o.CommonVerifyOptions.UseSignedTimestamps,
				TrustedRootPath:              o.CommonVerifyOptions.TrustedRootPath,
				Digest:                       o.Digest,
				DigestAlg:                    o.DigestAlg,
			}
			// We only use the blob if we are checking claims.
			if o.CheckClaims && len(args) == 0 && (o.Digest == "" || o.DigestAlg == "") {
				return fmt.Errorf("must provide path to blob or digest and digestAlg; run `cosign verify-blob-attestation -h` for more help")
			}
			var path string
			if len(args) > 0 {
				path = args[0]
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), ro.Timeout)
			defer cancel()

			if o.CommonVerifyOptions.IgnoreTlog && !o.CommonVerifyOptions.PrivateInfrastructure {
				ui.Warnf(ctx, ignoreTLogMessage, "blob attestation")
			}

			return v.Exec(ctx, path)
		},
	}

	o.AddFlags(cmd)
	return cmd
}
