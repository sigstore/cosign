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

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/spf13/cobra"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/inspect"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
)

func Inspect() *cobra.Command {
	o := &options.InspectOptions{}

	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "Inspect the signature and/or bundle on the supplied container image",
		Long: `Inspect a signature and/or bundle on an image by checking the claims
against the transparency log.`,
		Example: `  cosign inspect <image uri> [<image uri> ...]

  # inspect cosign claims and signing certificates on the image with the transparency log
  cosign inspect <IMAGE>

  # inspect multiple image signatures
  cosign inspect <IMAGE_1> <IMAGE_2> ...`,

		Args:             cobra.MinimumNArgs(1),
		PersistentPreRun: options.BindViper,
		RunE: func(cmd *cobra.Command, args []string) error {
			v := &inspect.InspectCommand{
				RegistryOptions: o.Registry,
				// CertVerifyOptions:            o.CertVerify,
				// CheckClaims:                  o.CheckClaims,
				// KeyRef:                       o.Key,
				// CertRef:                      o.CertVerify.Cert,
				// CertGithubWorkflowTrigger:    o.CertVerify.CertGithubWorkflowTrigger,
				// CertGithubWorkflowSha:        o.CertVerify.CertGithubWorkflowSha,
				// CertGithubWorkflowName:       o.CertVerify.CertGithubWorkflowName,
				// CertGithubWorkflowRepository: o.CertVerify.CertGithubWorkflowRepository,
				// CertGithubWorkflowRef:        o.CertVerify.CertGithubWorkflowRef,
				// CertChain:                    o.CertVerify.CertChain,
				// IgnoreSCT:                    o.CertVerify.IgnoreSCT,
				// SCTRef:                       o.CertVerify.SCT,
				// Sk:                           o.SecurityKey.Use,
				// Slot:                         o.SecurityKey.Slot,
				Output:     o.Output,
				RekorURL:   o.Rekor.URL,
				Attachment: o.Attachment,
				// Annotations:                  annotations,
				// HashAlgorithm:                hashAlgorithm,
				// SignatureRef:     o.SignatureRef,
				LocalImage:       o.LocalImage,
				Offline:          o.CommonInspectOptions.Offline,
				TSACertChainPath: o.CommonInspectOptions.TSACertChainPath,
				IgnoreTlog:       o.CommonInspectOptions.IgnoreTlog,
			}

			if o.Registry.AllowInsecure {
				v.NameOptions = append(v.NameOptions, name.Insecure)
			}

			if o.CommonInspectOptions.IgnoreTlog {
				fmt.Fprintln(
					os.Stderr,
					"**Warning** Skipping tlog verification is an insecure practice that lacks of transparency and auditability verification for the signature.",
				)
			}

			return v.Exec(cmd.Context(), args)
		},
	}

	o.AddFlags(cmd)
	return cmd
}

// func InspectAttestation() *cobra.Command {
// 	o := &options.InspectAttestationOptions{}
//
// 	cmd := &cobra.Command{
// 		Use:   "inspect-attestation",
// 		Short: "Inspect an attestation on the supplied container image",
// 		Long: `Inspect an attestation on an image by checking the claims
// against the transparency log.`,
// 		Example: `  cosign inspect-attestation <image uri> [<image uri> ...]
//
//   # inspect cosign attestations on the image against the transparency log
//   cosign inspect-attestation <IMAGE>
//
//   # inspect multiple images
//   cosign inspect-attestation <IMAGE_1> <IMAGE_2> ...`,
//
// 		Args:             cobra.MinimumNArgs(1),
// 		PersistentPreRun: options.BindViper,
// 		RunE: func(cmd *cobra.Command, args []string) error {
// 			v := &inspect.VerifyAttestationCommand{
// 				RegistryOptions: o.Registry,
// 				// CheckClaims:                  o.CheckClaims,
// 				// CertVerifyOptions:            o.CertVerify,
// 				// CertRef:                      o.CertVerify.Cert,
// 				// CertChain:                    o.CertVerify.CertChain,
// 				// CertGithubWorkflowTrigger:    o.CertVerify.CertGithubWorkflowTrigger,
// 				// CertGithubWorkflowSha:        o.CertVerify.CertGithubWorkflowSha,
// 				// CertGithubWorkflowName:       o.CertVerify.CertGithubWorkflowName,
// 				// CertGithubWorkflowRepository: o.CertVerify.CertGithubWorkflowRepository,
// 				// CertGithubWorkflowRef:        o.CertVerify.CertGithubWorkflowRef,
// 				// IgnoreSCT:                    o.CertVerify.IgnoreSCT,
// 				// SCTRef:                       o.CertVerify.SCT,
// 				// KeyRef:                       o.Key,
// 				// Sk:                           o.SecurityKey.Use,
// 				// Slot:                         o.SecurityKey.Slot,
// 				Output:   o.Output,
// 				RekorURL: o.Rekor.URL,
// 				// PredicateType: o.Predicate.Type,
// 				// Policies:                     o.Policies,
// 				LocalImage:       o.LocalImage,
// 				NameOptions:      o.Registry.NameOptions(),
// 				Offline:          o.CommonInspectOptions.Offline,
// 				TSACertChainPath: o.CommonInspectOptions.TSACertChainPath,
// 				IgnoreTlog:       o.CommonInspectOptions.IgnoreTlog,
// 			}
//
// 			return v.Exec(cmd.Context(), args)
// 		},
// 	}
//
// 	o.AddFlags(cmd)
// 	return cmd
// }

// func InspectBlob() *cobra.Command {
// 	o := &options.InspectBlobOptions{}
//
// 	cmd := &cobra.Command{
// 		Use:   "inspect-blob",
// 		Short: "Inspect the signature and/or bundle on the supplied blob",
// 		Long: `Inspect a signature and/or bundle on the supplied blob input using the specified key reference.
//
// The blob may be specified as a path to a file or - for stdin.`,
// 		Example: ` cosign inspect-blob | --signature <sig> <blob>
//
//   # Inspect a simple blob and message
//   cosign inspect-blob (--signature <sig path>|<sig url> msg)
//
//   # Inspect a signature from an environment variable
//   cosign inspect-blob --signature $sig msg
//
//   # Inspect a signature with public key provided by URL
//   cosign inspect-blob --signature $sig msg
//
//   # Inspect a signature with signature provided by URL
//   cosign inspect-blob --signature https://example.com/<SIG>
// `,
//
// 		Args:             cobra.ExactArgs(1),
// 		PersistentPreRun: options.BindViper,
// 		RunE: func(cmd *cobra.Command, args []string) error {
// 			// ko := options.KeyOpts{
// 			// 	KeyRef:               o.Key,
// 			// 	Sk:                   o.SecurityKey.Use,
// 			// 	Slot:                 o.SecurityKey.Slot,
// 			// 	RekorURL:             o.Rekor.URL,
// 			// 	BundlePath:           o.BundlePath,
// 			// 	RFC3161TimestampPath: o.RFC3161TimestampPath,
// 			// 	TSACertChainPath:     o.CommonVerifyOptions.TSACertChainPath,
// 			// }
// 			inspectBlobCmd := &inspect.InspectBlobCmd{
// 				// KeyOpts:                      ko,
// 				// CertVerifyOptions:            o.CertVerify,
// 				// CertRef:                      o.CertVerify.Cert,
// 				// CertChain:                    o.CertVerify.CertChain,
// 				SigRef: o.Signature,
// 				// CertGithubWorkflowTrigger:    o.CertVerify.CertGithubWorkflowTrigger,
// 				// CertGithubWorkflowSHA:        o.CertVerify.CertGithubWorkflowSha,
// 				// CertGithubWorkflowName:       o.CertVerify.CertGithubWorkflowName,
// 				// CertGithubWorkflowRepository: o.CertVerify.CertGithubWorkflowRepository,
// 				// CertGithubWorkflowRef:        o.CertVerify.CertGithubWorkflowRef,
// 				// IgnoreSCT:                    o.CertVerify.IgnoreSCT,
// 				// SCTRef:                       o.CertVerify.SCT,
// 				Offline:    o.CommonInspectOptions.Offline,
// 				IgnoreTlog: o.CommonInspectOptions.IgnoreTlog,
// 			}
// 			if err := inspectBlobCmd.Exec(cmd.Context(), args[0]); err != nil {
// 				return fmt.Errorf("inspecting blob %s: %w", args, err)
// 			}
// 			return nil
// 		},
// 	}
//
// 	o.AddFlags(cmd)
// 	return cmd
// }
//
// func InspectBlobAttestation() *cobra.Command {
// 	o := &options.InspectBlobAttestationOptions{}
//
// 	cmd := &cobra.Command{
// 		Use:   "inspect-blob-attestation",
// 		Short: "Inspect an attestation on the supplied blob",
// 		Long: `Inspect an attestation on the supplied blob input.
//
// The blob may be specified as a path to a file.`,
// 		Example: ` cosign inspect-blob-attestation --signature <sig> [path to BLOB]
//
//   # Inspect a simple blob attestation with a DSSE style signature
//   cosign inspect-blob-attestation (--signature <sig path>|<sig url>)[path to BLOB]
//
// `,
//
// 		Args:             cobra.ExactArgs(1),
// 		PersistentPreRun: options.BindViper,
// 		RunE: func(cmd *cobra.Command, args []string) error {
// 			// ko := options.KeyOpts{
// 			// 	KeyRef:               o.Key,
// 			// 	Sk:                   o.SecurityKey.Use,
// 			// 	Slot:                 o.SecurityKey.Slot,
// 			// 	RekorURL:             o.Rekor.URL,
// 			// 	BundlePath:           o.BundlePath,
// 			// 	RFC3161TimestampPath: o.RFC3161TimestampPath,
// 			// 	TSACertChainPath:     o.CommonVerifyOptions.TSACertChainPath,
// 			// }
// 			v := inspect.InspectBlobAttestationCommand{
// 				// KeyOpts:                      ko,
// 				PredicateType: o.PredicateOptions.Type,
// 				CheckClaims:   o.CheckClaims,
// 				SignaturePath: o.SignaturePath,
// 				// CertVerifyOptions:            o.CertVhttps://www.bloomberg.com/news/articles/2023-01-18/amazon-is-set-for-new-round-of-job-cuts-affecting-18-000-peoplehttps://www.bloomberg.com/news/articles/2023-01-18/amazon-is-set-for-new-round-of-job-cuts-affecting-18-000-peoplehttps://www.bloomberg.com/news/articles/2023-01-18/amazon-is-set-for-new-round-of-job-cuts-affecting-18-000-peoplehttps://www.bloomberg.com/news/articles/2023-01-18/amazon-is-set-for-new-round-of-job-cuts-affecting-18-000-peoplehttps://www.bloomberg.com/news/articles/2023-01-18/amazon-is-set-for-new-round-of-job-cuts-affecting-18-000-peoplehttps://www.bloomberg.com/news/articles/2023-01-18/amazon-is-set-for-new-round-of-job-cuts-affecting-18-000-peoplehttps://www.bloomberg.com/news/articles/2023-01-18/amazon-is-set-for-new-round-of-job-cuts-affecting-18-000-peoplehttps://www.bloomberg.com/news/articles/2023-01-18/amazon-is-set-for-new-round-of-job-cuts-affecting-18-000-peoplehttps://www.bloomberg.com/news/articles/2023-01-18/amazon-is-set-for-new-round-of-job-cuts-affecting-18-000-peoplehttps://www.bloomberg.com/news/articles/2023-01-18/amazon-is-set-for-new-round-of-job-cuts-affecting-18-000-peoplehttps://www.bloomberg.com/news/articles/2023-01-18/amazon-is-set-for-new-round-of-job-cuts-affecting-18-000-peopleerify,
// 				// CertRef:                      o.CertVerify.Cert,
// 				// CertChain:                    o.CertVerify.CertChain,
// 				// CertGithubWorkflowTrigger:    o.CertVerify.CertGithubWorkflowTrigger,
// 				// CertGithubWorkflowSHA:        o.CertVerify.CertGithubWorkflowSha,
// 				// CertGithubWorkflowName:       o.CertVerify.CertGithubWorkflowName,
// 				// CertGithubWorkflowRepository: o.CertVerify.CertGithubWorkflowRepository,
// 				// CertGithubWorkflowRef:        o.CertVerify.CertGithubWorkflowRef,
// 				// IgnoreSCT:                    o.CertVerify.IgnoreSCT,
// 				// SCTRef:                       o.CertVerify.SCT,
// 				Offline:    o.CommonInspectOptions.Offline,
// 				IgnoreTlog: o.CommonInspectOptions.IgnoreTlog,
// 			}
// 			if len(args) != 1 {
// 				return fmt.Errorf(
// 					"no path to blob passed in, run `cosign inspect-blob-attestation -h` for more help",
// 				)
// 			}
// 			return v.Exec(cmd.Context(), args[0])
// 		},
// 	}
//
// 	o.AddFlags(cmd)
// 	return cmd
// }
