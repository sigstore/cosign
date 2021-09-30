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

	"github.com/sigstore/cosign/cmd/cosign/cli/copy"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
)

func addCopy(topLevel *cobra.Command) {
	o := &options.CopyOptions{}

	cmd := &cobra.Command{
		Use:   "copy",
		Short: "Copy the supplied container image and signatures.",
		Example: `  cosign copy <source image> <destination image>

  # copy a container image and its signatures
  cosign copy example.com/src:latest example.com/dest:latest

  # copy the signatures only
  cosign copy -sig-only example.com/src example.com/dest

  # overwrite destination image and signatures
  cosign copy -f example.com/src example.com/dest`,

		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return copy.CopyCmd(cmd.Context(), o.Registry, args[0], args[1], o.SignatureOnly, o.Force)
		},
	}

	o.AddFlags(cmd)
	topLevel.AddCommand(cmd)
}
