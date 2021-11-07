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

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/sigstore/cosign/pkg/version"
)

func Version() *cobra.Command {
	var outputJSON bool

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Prints the cosign version",
		Long:  "Prints the cosign version",

		RunE: func(cmd *cobra.Command, args []string) error {
			v := version.GetVersionInfo()
			res := v.String()
			if outputJSON {
				j, err := v.JSONString()
				if err != nil {
					return errors.Wrap(err, "unable to generate JSON from version info")
				}
				res = j
			}
			fmt.Println(res)
			return nil
		},
	}

	cmd.Flags().BoolVar(&outputJSON, "json", false,
		"print JSON instead of text")

	ro.AddFlags(cmd)
	return cmd
}
