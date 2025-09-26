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

	"github.com/sigstore/cosign/v3/cmd/cosign/cli/download"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/spf13/cobra"
)

func Download() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "download",
		Short: "Provides utilities for downloading artifacts and attached artifacts in a registry",
	}

	cmd.AddCommand(
		downloadSignature(),
		downloadSBOM(),
		downloadAttestation(),
	)

	return cmd
}

func downloadSignature() *cobra.Command {
	o := &options.RegistryOptions{}

	cmd := &cobra.Command{
		Use:              "signature",
		Short:            "Download signatures from the supplied container image",
		Example:          "  cosign download signature <image uri>",
		Args:             cobra.ExactArgs(1),
		PersistentPreRun: options.BindViper,
		RunE: func(cmd *cobra.Command, args []string) error {
			return download.SignatureCmd(cmd.Context(), *o, args[0])
		},
	}

	o.AddFlags(cmd)

	return cmd
}

func downloadSBOM() *cobra.Command {
	o := &options.RegistryOptions{}
	do := &options.SBOMDownloadOptions{}

	cmd := &cobra.Command{
		Use:              "sbom",
		Short:            "DEPRECATED: Download SBOMs from the supplied container image",
		Long:             "Download SBOMs from the supplied container image\n\n" + options.SBOMAttachmentDeprecation,
		Example:          "  cosign download sbom <image uri>",
		Args:             cobra.ExactArgs(1),
		PersistentPreRun: options.BindViper,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(os.Stderr, options.SBOMAttachmentDeprecation)
			fmt.Fprintln(os.Stderr, "WARNING: Downloading SBOMs this way does not ensure its authenticity. If you want to ensure a tamper-proof SBOM, download it using 'cosign download attestation <image uri>'.")
			_, err := download.SBOMCmd(cmd.Context(), *o, *do, args[0], cmd.OutOrStdout())
			return err
		},
	}

	do.AddFlags(cmd)
	o.AddFlags(cmd)

	return cmd
}

func downloadAttestation() *cobra.Command {
	o := &options.RegistryOptions{}
	ao := &options.AttestationDownloadOptions{}

	cmd := &cobra.Command{
		Use:              "attestation",
		Short:            "Download in-toto attestations from the supplied container image",
		Example:          "  cosign download attestation <image uri> [--predicate-type]",
		Args:             cobra.ExactArgs(1),
		PersistentPreRun: options.BindViper,
		RunE: func(cmd *cobra.Command, args []string) error {
			return download.AttestationCmd(cmd.Context(), *o, *ao, args[0])
		},
	}

	o.AddFlags(cmd)
	ao.AddFlags(cmd)

	return cmd
}
