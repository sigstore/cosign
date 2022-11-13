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

	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/verify"
)

func Inspect() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "inspect the supplied container image, signed in keyless mode.",
		Long:  `inspect is useful for debugging images signed in keyless mode. It doesn't perform any verification and prints all signatures attached to the supplied image.`,
		Example: `cosign inspect <image uri> [<image uri> ...]

  # inspect a single image
  cosign inspect <IMAGE>

  # inspect multiple images
  cosign inspect <IMAGE_1> <IMAGE_2> ...`,

		Args:             cobra.MinimumNArgs(1),
		PersistentPreRun: options.BindViper,
		RunE: func(cmd *cobra.Command, args []string) error {
			v := verify.VerifyCommand{}
			return v.Exec(cmd.Context(), args)
		},
	}

	return cmd
}
