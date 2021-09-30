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
	"github.com/spf13/cobra"

	"github.com/sigstore/cosign/cmd/cosign/cli/attach"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
)

func addAttach(topLevel *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "attach",
		Short: "Provides utilities for attaching artifacts to other artifacts in a registry",
	}

	cmd.AddCommand(
		attachSignature(),
		attachSBOM(),
	)

	topLevel.AddCommand(cmd)
}

func attachSignature() *cobra.Command {
	o := &options.AttachSignatureOptions{}

	cmd := &cobra.Command{
		Use:     "signature",
		Short:   "Attach signatures to the supplied container image",
		Example: "cosign attach signature <image uri>",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return attach.SignatureCmd(cmd.Context(), o.Registry, o.Signature, o.Payload, args[0])
		},
	}

	o.AddFlags(cmd)

	return cmd
}

func attachSBOM() *cobra.Command {
	o := &options.AttachSBOMOptions{}

	cmd := &cobra.Command{
		Use:     "sbom",
		Short:   "Attach sbom to the supplied container image",
		Example: "cosign attach sbom <image uri>",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			mediaType, err := o.MediaType()
			if err != nil {
				return err
			}
			return attach.SBOMCmd(cmd.Context(), o.Registry, o.SBOM, mediaType, args[0])
		},
	}

	o.AddFlags(cmd)

	return cmd
}
