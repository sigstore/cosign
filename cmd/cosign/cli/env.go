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
	"sort"
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
			envVars := env.EnvironmentVariables()
			printEnv(envVars, o.ShowDescriptions, o.ShowSensitiveValues)

			return nil
		},
	}

	o.AddFlags(cmd)
	return cmd
}

// NB: printEnv intentionally takes map of env vars to make it easier to unit test it
func printEnv(envVars map[env.Variable]env.VariableOpts, showDescription, showSensitive bool) {
	// Sort keys to print them in a predictable order
	keys := sortEnvKeys(envVars)

	// Print known/registered environment variables
	for _, env := range keys {
		opts := envVars[env]

		// Get value of environment variable
		// NB: This package works with environment variables, so we ignore forbidigo linter.
		// We could use env.Getenv here, but that would make unit testing too complicated
		// as unit tests are using non-registered variables
		val := os.Getenv(env.String()) //nolint:forbidigo

		// If showDescription is set, print description for that variable
		if showDescription {
			fmt.Printf("# %s %s\n", env.String(), opts.Description)
			fmt.Printf("# Expects: %s\n", opts.Expects)
		}

		// If variable is sensitive, and we don't want to show sensitive values,
		// print environment variable name and some asterisk symbols.
		// If sensitive variable isn't set or doesn't have any value, we'll just
		// print like non-sensitive variable
		if opts.Sensitive && !showSensitive && val != "" {
			fmt.Printf("%s=\"******\"\n", env.String())
		} else {
			fmt.Printf("%s=%q\n", env.String(), val)
		}
	}

	// Print not registered environment variables
	var nonRegEnv []string
	for _, e := range os.Environ() {
		// Prefixes to look for. err on the side of showing too much rather
		// than too little. We'll only output things that have values set.
		for _, prefix := range []string{
			// We want to print eventually non-registered cosign variables (even if this shouldn't happen)
			"COSIGN_",
			// Can modify Sigstore/TUF client behavior - https://github.com/sigstore/sigstore/blob/35d6a82c15183f7fe7a07eca45e17e378aa32126/pkg/tuf/client.go#L52
			"SIGSTORE_",
			"TUF_",
		} {
			if strings.HasPrefix(e, prefix) {
				// Skip registered environment variables (those are already printed above).
				// os.Environ returns key=value pairs, so we use split by '=' to get the key
				key := strings.Split(e, "=")[0]
				if _, ok := envVars[env.Variable(key)]; ok {
					continue
				}
				nonRegEnv = append(nonRegEnv, e)
			}
		}
	}
	if len(nonRegEnv) > 0 && showDescription {
		fmt.Println("# Environment variables below are not registered with cosign,\n# but might still influence cosign's behavior.")
	}
	for _, e := range nonRegEnv {
		fmt.Println(e)
	}
}

func sortEnvKeys(envVars map[env.Variable]env.VariableOpts) []env.Variable {
	keys := []env.Variable{}
	for k := range envVars {
		keys = append(keys, k)
	}

	sort.Slice(keys, func(i, j int) bool {
		return strings.Compare(keys[i].String(), keys[j].String()) < 0
	})

	return keys
}
