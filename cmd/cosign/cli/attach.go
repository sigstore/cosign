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
	"errors"
	"fmt"
	"os"

	"github.com/sigstore/cosign/v3/cmd/cosign/cli/attach"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/spf13/cobra"
)

func Attach() *cobra.Command {
	cmd := &cobra.Command{
		Use:        "attach",
		Short:      "Provides utilities for attaching artifacts to other artifacts in a registry",
		Deprecated: "attach will be removed in v4.0.0 (see https://github.com/sigstore/cosign/issues/4696). Instead, please use oras for attaching artifacts to other artifacts in a registry",
	}

	cmd.AddCommand(
		attachBundle(),
		attachSBOM(),
	)

	return cmd
}

func attachBundle() *cobra.Command {
	o := &options.AttachBundleOptions{}

	cmd := &cobra.Command{
		Use:     "bundle",
		Aliases: []string{"signature", "attestation"},
		Short:   "Attach bundles to the supplied container image",
		Example: `  cosign attach bundle --bundle <bundle-path> <image uri>

  # Attach bundle to a supplied image
  cosign attach bundle --bundle <bundle.sigstore.json> $IMAGE

  # Attach multiple bundles to a supplied image
  cosign attach bundle --bundle <bundle1.json> --bundle <bundle2.json> $IMAGE

  # Legacy signature and attestation subcommand aliases are also supported
  cosign attach signature --bundle <bundle.sigstore.json> $IMAGE
  cosign attach attestation --bundle <bundle.sigstore.json> $IMAGE`,
		PersistentPreRun: options.BindViper,
		Args:             cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(o.BundlePaths) == 0 {
				return errors.New("must specify --bundle")
			}
			return attach.BundleCmd(cmd.Context(), o.Registry, o.BundlePaths, args[0])
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
