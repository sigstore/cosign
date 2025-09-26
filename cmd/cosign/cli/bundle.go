//
// Copyright 2024 The Sigstore Authors.
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

	"github.com/sigstore/cosign/v3/cmd/cosign/cli/bundle"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/spf13/cobra"
)

func Bundle() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bundle",
		Short: "Interact with a Sigstore protobuf bundle",
		Long:  "Tools for interacting with a Sigstore protobuf bundle",
	}

	cmd.AddCommand(bundleCreate())

	return cmd
}

func bundleCreate() *cobra.Command {
	o := &options.BundleCreateOptions{}

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a Sigstore protobuf bundle",
		Long:  "Create a Sigstore protobuf bundle by supplying signed material",
		RunE: func(cmd *cobra.Command, _ []string) error {
			bundleCreateCmd := &bundle.CreateCmd{
				Artifact:             o.Artifact,
				AttestationPath:      o.AttestationPath,
				BundlePath:           o.BundlePath,
				CertificatePath:      o.CertificatePath,
				IgnoreTlog:           o.IgnoreTlog,
				KeyRef:               o.KeyRef,
				Out:                  o.Out,
				RekorURL:             o.RekorURL,
				RFC3161TimestampPath: o.RFC3161TimestampPath,
				SignaturePath:        o.SignaturePath,
				Sk:                   o.Sk,
				Slot:                 o.Slot,
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), ro.Timeout)
			defer cancel()

			return bundleCreateCmd.Exec(ctx)
		},
	}

	o.AddFlags(cmd)
	return cmd
}
