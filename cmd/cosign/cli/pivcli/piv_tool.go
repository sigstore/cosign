// +build !pivkeydisabled

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

package pivcli

import (
	"context"
	"flag"

	"github.com/peterbourgon/ff/v3/ffcli"
)

func PivKey() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign piv-tool", flag.ExitOnError)
		force   = flagset.Bool("f", false, "skip warnings and confirmations")
	)

	if *force {
		Confirm = func(_ string) bool { return true }
	}

	return &ffcli.Command{
		Name:        "piv-tool",
		ShortUsage:  "cosign piv-tool",
		ShortHelp:   "piv-tool contains commands to manage a hardware token",
		FlagSet:     flagset,
		Subcommands: []*ffcli.Command{SetManagementKey(), SetPin(), SetPuk(), Unblock(), Attestation(), GenerateKey(), ResetKey()},
		Exec: func(ctx context.Context, args []string) error {
			return flag.ErrHelp
		},
	}
}

func SetManagementKey() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign piv-tool set-management-key", flag.ExitOnError)

		oldKey    = flagset.String("old-key", "", "existing management key, uses default if empty")
		newKey    = flagset.String("new-key", "", "new management key, uses default if empty")
		randomKey = flagset.Bool("random-management-key", false, "if set to true, generates a new random management key and deletes it after")
	)

	return &ffcli.Command{
		Name:       "set-management-key",
		ShortUsage: "cosign piv-tool set-management-key",
		ShortHelp:  "set-management-key sets the management key of a hardware token",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			return SetManagementKeyCmd(ctx, *oldKey, *newKey, *randomKey)
		},
	}
}

func SetPuk() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign piv-tool set-puk", flag.ExitOnError)

		oldPuk = flagset.String("old-puk", "", "existing puk, uses default if empty")
		newPuk = flagset.String("new-puk", "", "new puk, uses default if empty")
	)

	return &ffcli.Command{
		Name:       "set-puk",
		ShortUsage: "cosign piv-tool set-puk",
		ShortHelp:  "set-puk contains commands to manage a hardware token",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			return SetPukCmd(ctx, *oldPuk, *newPuk)
		},
	}
}

func SetPin() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign piv-tool set-pin", flag.ExitOnError)

		oldPin = flagset.String("old-pin", "", "existing pin, uses default if empty")
		newPin = flagset.String("new-pin", "", "new pin, uses default if empty")
	)

	return &ffcli.Command{
		Name:       "set-pin",
		ShortUsage: "cosign piv-tool set-pin",
		ShortHelp:  "set-pin contains commands to manage a hardware token",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			return SetPinCmd(ctx, *oldPin, *newPin)
		},
	}
}

func Unblock() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign piv-tool unblock", flag.ExitOnError)

		oldPuk = flagset.String("puk", "", "existing puk, uses default if empty")
		newPin = flagset.String("new-pin", "", "new pin, uses default if empty")
	)

	return &ffcli.Command{
		Name:       "unblock",
		ShortUsage: "cosign piv-tool unblock",
		ShortHelp:  "unblock contains commands to manage a hardware token",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			return UnblockCmd(ctx, *oldPuk, *newPin)
		},
	}
}

func Attestation() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign piv-tool attestation", flag.ExitOnError)
	)

	return &ffcli.Command{
		Name:       "attestation",
		ShortUsage: "cosign piv-tool attestation",
		ShortHelp:  "attestation contains commands to manage a hardware token",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			_, err := AttestationCmd(ctx)
			return err
		},
	}
}

func GenerateKey() *ffcli.Command {
	var (
		flagset       = flag.NewFlagSet("cosign piv-tool generate-key", flag.ExitOnError)
		managementKey = flagset.String("management-key", "", "management key, uses default if empty")
		randomKey     = flagset.Bool("random-management-key", false, "if set to true, generates a new random management key and deletes it after")
	)

	return &ffcli.Command{
		Name:       "generate-key",
		ShortUsage: "cosign piv-tool generate-key",
		ShortHelp:  "generate-key generates a new signing key on the hardware token",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			return GenerateKeyCmd(ctx, *managementKey, *randomKey)
		},
	}
}

func ResetKey() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign piv-tool reset", flag.ExitOnError)
	)

	return &ffcli.Command{
		Name:       "reset",
		ShortUsage: "cosign piv-tool reset",
		ShortHelp:  "reset resets the hardware token completely",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			return ResetKeyCmd(ctx)
		},
	}
}
