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

	"github.com/sigstore/cosign/v3/cmd/cosign/cli/attach"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/spf13/cobra"
)

func Attach() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attach",
		Short: "Provides utilities for attaching artifacts to other artifacts in a registry",
	}

	cmd.AddCommand(
		attachSignature(),
		attachSBOM(),
		attachAttestation(),
	)

	return cmd
}

func attachSignature() *cobra.Command {
	o := &options.AttachSignatureOptions{}

	cmd := &cobra.Command{
		Use:   "signature",
		Short: "Attach signatures to the supplied container image",
		Example: `  cosign attach signature [--payload <path>] [--signature < path>] [--rekor-response < path>] <image uri>

		cosign attach signature command attaches payload, signature, rekor-bundle, etc in a new layer of provided image.
		
		# Attach signature can attach payload to a supplied image
		cosign attach signature --payload <payload.json>  $IMAGE

		# Attach signature can attach payload, signature to a supplied image
		cosign attach signature --payload <payload.json> --signature <base64 signature file> $IMAGE

		# Attach signature can attach payload, signature, time stamped response to a supplied image
		cosign attach signature --payload <payload.json> --signature <base64 signature file> --tsr=<file> $IMAGE

		# Attach signature attaches payload, signature and rekor-bundle via rekor-response to a supplied image
		cosign attach signature --payload <payload.json> --signature <base64 signature file>  --rekor-response <proper rekor-response format file> $IMAGE

		# Attach signature attaches payload, signature and rekor-bundle directly to a supplied image
		cosign attach signature --payload <payload.json> --signature <base64 signature file>  --rekor-response <rekor-bundle file> $IMAGE`,
		PersistentPreRun: options.BindViper,
		Args:             cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return attach.SignatureCmd(cmd.Context(), o.Registry, o.Signature, o.Payload, o.Cert, o.CertChain, o.TimeStampedSig, o.RekorBundle, args[0])
		},
	}

	o.AddFlags(cmd)

	return cmd
}

func attachSBOM() *cobra.Command {
	o := &options.AttachSBOMOptions{}

	cmd := &cobra.Command{
		Use:              "sbom",
		Short:            "DEPRECATED: Attach sbom to the supplied container image",
		Long:             "Attach sbom to the supplied container image\n\n" + options.SBOMAttachmentDeprecation,
		Example:          "  cosign attach sbom <image uri>",
		Args:             cobra.ExactArgs(1),
		PersistentPreRun: options.BindViper,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(os.Stderr, options.SBOMAttachmentDeprecation)
			mediaType, err := o.MediaType()
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "WARNING: Attaching SBOMs this way does not sign them. To sign them, use 'cosign attest --predicate %s --key <key path>'.\n", o.SBOM)
			return attach.SBOMCmd(cmd.Context(), o.Registry, o.RegistryExperimental, o.SBOM, mediaType, args[0])
		},
	}

	o.AddFlags(cmd)

	return cmd
}

func attachAttestation() *cobra.Command {
	o := &options.AttachAttestationOptions{}

	cmd := &cobra.Command{
		Use:   "attestation",
		Short: "Attach attestation to the supplied container image",
		Example: `  cosign attach attestation --attestation <attestation file path> <image uri>

  # attach attestations from multiple files to a container image
  cosign attach attestation --attestation <attestation file path> --attestation <attestation file path> <image uri>

  # attach attestation from bundle files in form of JSONLines to a container image
  # https://github.com/in-toto/attestation/blob/main/spec/v1.0-draft/bundle.md
  cosign attach attestation --attestation <attestation bundle file path> <image uri>
`,

		Args:             cobra.MinimumNArgs(1),
		PersistentPreRun: options.BindViper,
		RunE: func(cmd *cobra.Command, args []string) error {
			return attach.AttestationCmd(cmd.Context(), o.Registry, o.Attestations, args[0])
		},
	}

	o.AddFlags(cmd)

	return cmd
}
