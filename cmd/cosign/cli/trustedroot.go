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

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/trustedroot"
	"github.com/spf13/cobra"
)

func TrustedRoot() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trusted-root",
		Short: "Interact with a Sigstore protobuf trusted root",
		Long:  "Tools for interacting with a Sigstore protobuf trusted root",
	}

	cmd.AddCommand(trustedRootCreate())

	return cmd
}

func trustedRootCreate() *cobra.Command {
	o := &options.TrustedRootCreateOptions{}

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a Sigstore protobuf trusted root",
		Long:  "Create a Sigstore protobuf trusted root by supplying verification material",
		RunE: func(cmd *cobra.Command, _ []string) error {
			trCreateCmd := &trustedroot.CreateCmd{
				CertChain:        o.CertChain,
				FulcioURI:        o.FulcioURI,
				CtfeKeyPath:      o.CtfeKeyPath,
				CtfeStartTime:    o.CtfeStartTime,
				CtfeEndTime:      o.CtfeEndTime,
				CtfeURL:          o.CtfeURL,
				Out:              o.Out,
				RekorKeyPath:     o.RekorKeyPath,
				RekorStartTime:   o.RekorStartTime,
				RekorEndTime:     o.RekorEndTime,
				RekorURL:         o.RekorURL,
				TSACertChainPath: o.TSACertChainPath,
				TSAURI:           o.TSAURI,
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), ro.Timeout)
			defer cancel()

			return trCreateCmd.Exec(ctx)
		},
	}

	o.AddFlags(cmd)
	return cmd
}
