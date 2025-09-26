// Copyright 2024 The Sigstore Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cli

import (
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/debug"
	"github.com/spf13/cobra"
)

func Debug() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "debug",
		Hidden: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	cmd.AddCommand(debugProviders())
	return cmd
}

func debugProviders() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "providers",
		Short: "Show enabled/disabled OIDC providers.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return debug.ProviderCmd(cmd.Context(), cmd.OutOrStdout())
		},
	}
	return cmd
}
