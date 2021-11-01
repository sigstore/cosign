//go:build pkcs11key
// +build pkcs11key

// Copyright 2021 The Sigstore Authors
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
	"github.com/spf13/cobra"

	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/pkcs11cli"
)

var pkcs11ToolForce bool

func PKCS11Tool() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pkcs11-tool",
		Short: "Provides utilities for retrieving information from a PKCS11 token.",
	}

	cmd.AddCommand(
		pkcs11ToolListTokens(),
		PKCS11ToolListKeysUrisOptions(),
	)

	// TODO: drop -f in favor of --no-input only
	// TODO: use the force flag.
	cmd.PersistentFlags().BoolVarP(&pkcs11ToolForce, "no-input", "f", false,
		"skip warnings and confirmations")

	return cmd
}

func pkcs11ToolListTokens() *cobra.Command {
	o := &options.PKCS11ToolListTokensOptions{}

	cmd := &cobra.Command{
		Use:   "list-tokens",
		Short: "list-tokens lists all PKCS11 tokens linked to a PKCS11 module",
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return pkcs11cli.ListTokensCmd(cmd.Context(), o.ModulePath)
		},
	}

	o.AddFlags(cmd)

	return cmd
}

func PKCS11ToolListKeysUrisOptions() *cobra.Command {
	o := &options.PKCS11ToolListKeysUrisOptions{}

	cmd := &cobra.Command{
		Use:   "list-keys-uris",
		Short: "list-keys-uris lists URIs of all keys in a PKCS11 token",
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return pkcs11cli.ListKeysUrisCmd(cmd.Context(), o.ModulePath, o.SlotId, o.Pin)
		},
	}

	o.AddFlags(cmd)

	return cmd
}
