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
	"flag"

	"github.com/spf13/cobra"

	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/triangulate"
)

func Triangulate() *cobra.Command {
	o := &options.TriangulateOptions{}

	cmd := &cobra.Command{
		Use:     "triangulate",
		Short:   "Outputs the located cosign image reference. This is the location cosign stores the specified artifact type.",
		Example: "  cosign triangulate <IMAGE>",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return flag.ErrHelp
			}
			return triangulate.MungeCmd(cmd.Context(), o.Registry, args[0], o.Type)
		},
	}

	o.AddFlags(cmd)
	return cmd
}
