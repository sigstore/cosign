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
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/copy"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/spf13/cobra"
)

func Copy() *cobra.Command {
	o := &options.CopyOptions{}

	cmd := &cobra.Command{
		Use:   "copy",
		Short: "Copy the supplied container image and signatures.",
		Example: `  cosign copy <source image> <destination image>

  # copy a container image and its signatures
  cosign copy example.com/src:latest example.com/dest:latest

  # copy the signatures only
  cosign copy --only=sig example.com/src example.com/dest

  # copy the signatures, attestations, sbom only
  cosign copy --only=sig,att,sbom example.com/src example.com/dest

  # overwrite destination image and signatures
  cosign copy -f example.com/src example.com/dest

  # copy a container image and its signatures for a specific platform
  cosign copy --platform=linux/amd64 example.com/src:latest example.com/dest:latest`,

		Args:             cobra.ExactArgs(2),
		PersistentPreRun: options.BindViper,
		RunE: func(cmd *cobra.Command, args []string) error {
			return copy.CopyCmd(cmd.Context(), o.Registry, args[0], args[1], o.SignatureOnly, o.Force, o.CopyOnly, o.Platform)
		},
	}

	o.AddFlags(cmd)
	return cmd
}
