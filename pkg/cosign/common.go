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

package cosign

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"
)

// skipConfirmation is a global variable to store whether or not the user has provided
// the --yes flag to skip all confirmation prompts
var skipConfirmation bool

func SetSkipConfirmation(skip bool) {
	skipConfirmation = skip
}

// TODO need to centralize this logic
func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// ConfirmPrompt prompts the user for confirmation for an action. Supports skipping
// the confirmation prompt when the global skipConfirmation is set.
func ConfirmPrompt(msg string) (bool, error) {
	if skipConfirmation {
		return skipConfirmation, nil
	}

	fmt.Fprintf(os.Stderr, "%s\n\nAre you sure you want to continue? (y/[N]): ", msg)
	reader := bufio.NewReader(os.Stdin)
	r, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}
	return strings.Trim(r, "\n") == "Y" || strings.Trim(r, "\n") == "y", nil
}

// ConfirmPromptDestructive prompts the user for confirmation for an action. Ignores
// skipConfirmation.
func ConfirmPromptDestructive(msg string) (bool, error) {
	fmt.Fprintf(os.Stderr, "%s\n\nAre you sure you want to continue? (y/[N]): ", msg)
	reader := bufio.NewReader(os.Stdin)
	r, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}
	return strings.Trim(r, "\n") == "Y" || strings.Trim(r, "\n") == "y", nil
}

func GetPassFromTerm(confirm bool) ([]byte, error) {
	fmt.Fprint(os.Stderr, "Enter password for private key: ")
	// Unnecessary convert of syscall.Stdin on *nix, but Windows is a uintptr
	// nolint:unconvert
	pw1, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return nil, err
	}
	fmt.Fprintln(os.Stderr)
	if !confirm {
		return pw1, nil
	}
	fmt.Fprint(os.Stderr, "Enter password for private key again: ")
	// Unnecessary convert of syscall.Stdin on *nix, but Windows is a uintptr
	// nolint:unconvert
	confirmpw, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}

	if string(pw1) != string(confirmpw) {
		return nil, errors.New("passwords do not match")
	}
	return pw1, nil
}

func IsTerminal() bool {
	stat, _ := os.Stdin.Stat()
	return (stat.Mode() & os.ModeCharDevice) != 0
}
