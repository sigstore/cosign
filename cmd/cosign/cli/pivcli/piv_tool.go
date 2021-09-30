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

package pivcli

import (
	"context"
	"flag"

	"github.com/peterbourgon/ff/v3/ffcli"
)

// PivKey subcommand for ffcli.
// Deprecated: this will be deleted when the migration from ffcli to cobra is done.
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
		ShortHelp:   "Provides utilities for managing a hardware token",
		FlagSet:     flagset,
		Subcommands: []*ffcli.Command{SetManagementKey(), SetPin(), SetPuk(), Unblock(), Attestation(), GenerateKey(), ResetKey()},
		Exec: func(ctx context.Context, args []string) error {
			panic("this command is now implemented in cobra.")
		},
	}
}

// SetManagementKey subcommand for ffcli.
// Deprecated: this will be deleted when the migration from ffcli to cobra is done.
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
			_ = oldKey
			_ = newKey
			_ = randomKey
			panic("this command is now implemented in cobra.")
		},
	}
}

// SetPuk subcommand for ffcli.
// Deprecated: this will be deleted when the migration from ffcli to cobra is done.
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
			_ = oldPuk
			_ = newPuk
			panic("this command is now implemented in cobra.")
		},
	}
}

// SetPin subcommand for ffcli.
// Deprecated: this will be deleted when the migration from ffcli to cobra is done.
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
			_ = oldPin
			_ = newPin
			panic("this command is now implemented in cobra.")
		},
	}
}

// Unblock subcommand for ffcli.
// Deprecated: this will be deleted when the migration from ffcli to cobra is done.
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
			_ = oldPuk
			_ = newPin
			panic("this command is now implemented in cobra.")
		},
	}
}

// Attestation subcommand for ffcli.
// Deprecated: this will be deleted when the migration from ffcli to cobra is done.
func Attestation() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign piv-tool attestation", flag.ExitOnError)
		output  = flagset.String("output", "text", "format to output attestation information in. text|json, default text.")
		slot    = flagset.String("slot", "", "Slot to use for generated key (authentication|signature|card-authentication|key-management)")
	)

	return &ffcli.Command{
		Name:       "attestation",
		ShortUsage: "cosign piv-tool attestation",
		ShortHelp:  "attestation contains commands to manage a hardware token",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			_ = output
			_ = slot
			panic("this command is now implemented in cobra.")
		},
	}
}

// GenerateKey subcommand for ffcli.
// Deprecated: this will be deleted when the migration from ffcli to cobra is done.
func GenerateKey() *ffcli.Command {
	var (
		flagset       = flag.NewFlagSet("cosign piv-tool generate-key", flag.ExitOnError)
		managementKey = flagset.String("management-key", "", "management key, uses default if empty")
		randomKey     = flagset.Bool("random-management-key", false, "if set to true, generates a new random management key and deletes it after")
		slot          = flagset.String("slot", "", "Slot to use for generated key (authentication|signature|card-authentication|key-management)")
		pinPolicy     = flagset.String("pin-policy", "", "PIN policy for slot (never|once|always)")
		touchPolicy   = flagset.String("touch-policy", "", "Touch policy for slot (never|always|cached)")
	)

	return &ffcli.Command{
		Name:       "generate-key",
		ShortUsage: "cosign piv-tool generate-key",
		ShortHelp:  "generate-key generates a new signing key on the hardware token",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			_ = flagset
			_ = managementKey
			_ = randomKey
			_ = slot
			_ = pinPolicy
			_ = touchPolicy
			panic("this command is now implemented in cobra.")
		},
	}
}

// ResetKey subcommand for ffcli.
// Deprecated: this will be deleted when the migration from ffcli to cobra is done.
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
			panic("this command is now implemented in cobra.")
		},
	}
}
