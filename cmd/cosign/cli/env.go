//
// Copyright 2022 The Sigstore Authors.
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
	"strings"

	"github.com/spf13/cobra"

	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/pkg/cosign/env"
)

func Env() *cobra.Command {
	o := &options.EnvOptions{}

	cmd := &cobra.Command{
		Use:   "env",
		Short: "Prints Cosign environment variables",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Print COSIGN_ environment variables
			env.PrintEnv(o.ShowDescriptions, o.ShowSensitiveValues)

			// Print external environment variables (SIGSTORE_ and TUF_)
			for _, e := range getExternalEnv() {
				fmt.Println(e)
			}

			return nil
		},
	}

	o.AddFlags(cmd)
	return cmd
}

func getExternalEnv() []string {
	out := []string{}
	for _, e := range os.Environ() {
		// Prefixes to look for. err on the side of showing too much rather
		// than too little. We'll only output things that have values set.
		for _, prefix := range []string{
			// Can modify Sigstore/TUF client behavior - https://github.com/sigstore/sigstore/blob/35d6a82c15183f7fe7a07eca45e17e378aa32126/pkg/tuf/client.go#L52
			"SIGSTORE_",
			"TUF_",
		} {
			if strings.HasPrefix(e, prefix) {
				out = append(out, e)
				continue
			}
		}
	}
	return out
}
