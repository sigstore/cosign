//go:build pivkey && cgo
// +build pivkey,cgo

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
	"encoding/json"

	"github.com/spf13/cobra"

	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/pivcli"
)

var pivToolForce bool

func addPIVTool(topLevel *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "piv-tool",
		Short: "Provides utilities for managing a hardware token",
	}

	cmd.AddCommand(
		pivToolSetManagementKey(),
		pivToolSetPIN(),
		pivToolSetPUK(),
		pivToolUnblock(),
		pivToolAttestation(),
		pivToolGenerateKey(),
		pivToolResetKey(),
	)

	// TODO: drop -f in favor of --no-input only
	// TODO: use the force flag.
	cmd.PersistentFlags().BoolVarP(&pivToolForce, "no-input", "f", false,
		"skip warnings and confirmations")

	topLevel.AddCommand(cmd)
}

func pivToolSetManagementKey() *cobra.Command {
	o := &options.PIVToolSetManagementKeyOptions{}

	cmd := &cobra.Command{
		Use:   "set-management-key",
		Short: "sets the management key of a hardware token",
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return pivcli.SetManagementKeyCmd(cmd.Context(), o.OldKey, o.NewKey, o.RandomKey)
		},
	}

	o.AddFlags(cmd)

	return cmd
}

func pivToolSetPIN() *cobra.Command {
	o := &options.PIVToolSetPINOptions{}

	cmd := &cobra.Command{
		Use:   "set-pin",
		Short: "sets the PIN on a hardware token",
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return pivcli.SetPinCmd(cmd.Context(), o.OldPIN, o.NewPIN)
		},
	}

	o.AddFlags(cmd)

	return cmd
}

func pivToolSetPUK() *cobra.Command {
	o := &options.PIVToolSetPUKOptions{}

	cmd := &cobra.Command{
		Use:   "set-puk",
		Short: "sets the PUK on a hardware token",
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return pivcli.SetPukCmd(cmd.Context(), o.OldPUK, o.NewPUK)
		},
	}

	o.AddFlags(cmd)

	return cmd
}

func pivToolUnblock() *cobra.Command {
	o := &options.PIVToolUnblockOptions{}

	cmd := &cobra.Command{
		Use:   "unblock",
		Short: "unblocks the hardware token, sets a new PIN",
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return pivcli.UnblockCmd(cmd.Context(), o.PUK, o.NewPIN)
		},
	}

	o.AddFlags(cmd)

	return cmd
}

func pivToolAttestation() *cobra.Command {
	o := &options.PIVToolAttestationOptions{}

	cmd := &cobra.Command{
		Use:   "attestation",
		Short: "attestation contains commands to manage a hardware token",
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := pivcli.AttestationCmd(cmd.Context(), o.Slot)
			switch o.Output {
			case "text":
				a.Output(cmd.OutOrStdout(), cmd.OutOrStderr())
			case "json":
				b, err := json.Marshal(a)
				if err != nil {
					return err
				}
				cmd.Println(string(b))
			}
			return err
		},
	}

	o.AddFlags(cmd)

	return cmd
}

func pivToolGenerateKey() *cobra.Command {
	o := &options.PIVToolGenerateKeyOptions{}

	cmd := &cobra.Command{
		Use:   "generate-key",
		Short: "generate-key generates a new signing key on the hardware token",
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return pivcli.GenerateKeyCmd(cmd.Context(), o.ManagementKey, o.RandomKey,
				o.Slot, o.PINPolicy, o.TouchPolicy)
		},
	}

	o.AddFlags(cmd)

	return cmd
}

func pivToolResetKey() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reset",
		Short: "reset resets the hardware token completely",
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return pivcli.ResetKeyCmd(cmd.Context())
		},
	}

	return cmd
}
