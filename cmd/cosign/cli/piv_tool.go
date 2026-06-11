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

	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/pivcli"
	"github.com/spf13/cobra"
)

var pivToolForce bool

func PIVTool() *cobra.Command {
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

	return cmd
}

func pivToolSetManagementKey() *cobra.Command {
	o := &options.PIVToolSetManagementKeyOptions{}

	cmd := &cobra.Command{
		Use:              "set-management-key",
		Short:            "Set the management key of a hardware token",
		Example: `  # set a new management key interactively (uses defaults if flags omitted)
  cosign piv-tool set-management-key

  # set a random management key
  cosign piv-tool set-management-key --random-management-key

  # set a specific new management key
  cosign piv-tool set-management-key --old-key <old-key> --new-key <new-key>`,
		Args:             cobra.ExactArgs(0),
		PersistentPreRun: options.BindViper,
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
		Use:              "set-pin",
		Short:            "Set the PIN on a hardware token",
		Example: `  # set a new PIN interactively (uses defaults if flags omitted)
  cosign piv-tool set-pin

  # set a specific PIN
  cosign piv-tool set-pin --old-pin <old-pin> --new-pin <new-pin>`,
		Args:             cobra.ExactArgs(0),
		PersistentPreRun: options.BindViper,
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
		Short: "Set the PUK on a hardware token",
		Example: `  # set a new PUK interactively (uses defaults if flags omitted)
  cosign piv-tool set-puk

  # set a specific PUK
  cosign piv-tool set-puk --old-puk <old-puk> --new-puk <new-puk>`,
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
		Short: "Unblock a hardware token and set a new PIN",
		Example: `  # unblock the token using the PUK and set a new PIN
  cosign piv-tool unblock --puk <puk> --new-PIN <new-pin>`,
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
		Short: "Manage hardware token attestations",
		Example: `  # print attestation information as text
  cosign piv-tool attestation --slot 9c

  # print attestation information as JSON
  cosign piv-tool attestation --slot 9c --output json`,
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
		Short: "Generate a new signing key on the hardware token",
		Example: `  # generate a key with default settings (slot 9c, always-touch policy)
  cosign piv-tool generate-key

  # generate a key in a specific slot with custom PIN and touch policies
  cosign piv-tool generate-key --slot 9c --pin-policy once --touch-policy always`,
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
		Short: "Reset the hardware token completely",
		Example: `  cosign piv-tool reset`,
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return pivcli.ResetKeyCmd(cmd.Context())
		},
	}

	return cmd
}
