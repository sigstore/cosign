// Copyright 2026 The Sigstore Authors.
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

package updatekeypair

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/cosign/env"
)

var (
	// Read is for fuzzing
	Read = readPasswordFn
)

// UpdateKeyPairCmd re-encrypts the private key at keyPath with a new password.
// The user is prompted for the current password (to decrypt) and then twice for
// the new password (to re-encrypt with confirmation).
// nolint
func UpdateKeyPairCmd(_ context.Context, keyPath string) error {
	keyBytes, err := os.ReadFile(filepath.Clean(keyPath))
	if err != nil {
		return fmt.Errorf("reading key file %q: %w", keyPath, err)
	}

	// Obtain the current (old) password.
	currentPass, err := GetCurrentPass(false)
	if err != nil {
		return fmt.Errorf("reading current password: %w", err)
	}

	// Re-encrypt with the new password (pf is called with confirm=true inside UpdateKeyPair).
	updatedKeyBytes, err := cosign.UpdateKeyPair(keyBytes, currentPass, GetNewPass)
	if err != nil {
		return err
	}

	if err := os.WriteFile(keyPath, updatedKeyBytes, 0600); err != nil {
		return fmt.Errorf("writing updated key file %q: %w", keyPath, err)
	}

	fmt.Fprintln(os.Stderr, "Private key password updated in", keyPath)
	return nil
}

// GetCurrentPass reads the current (old) password used to decrypt the key.
func GetCurrentPass(confirm bool) ([]byte, error) {
	return Read(env.VariablePassword, confirm)
}

// GetNewPass reads the new password used to re-encrypt the key.
func GetNewPass(confirm bool) ([]byte, error) {
	return Read(env.VariableNewPassword, confirm)
}

// readPasswordFn reads the password for encryption or decryption.
// It uses the specified environment variable if set, otherwise prompts interactively.
// Piped-in passwords are not supported; use the environment variable for scripting.
func readPasswordFn(envVar env.Variable, confirm bool) ([]byte, error) {
	if pw, ok := env.LookupEnv(envVar); ok {
		return []byte(pw), nil
	}
	if cosign.IsTerminal() {
		if envVar == env.VariablePassword {
			return cosign.GetPassFromTermWithPrompt(confirm, "Enter current password for private key")
		}
		if envVar == env.VariableNewPassword {
			return cosign.GetPassFromTermWithPrompt(confirm, "Enter new password for private key")
		}
		return nil, fmt.Errorf("unsupported environment variable: %s", envVar)
	}
	return nil, fmt.Errorf("password not provided in environment variable %s and cannot prompt in non-interactive terminal", envVar)
}
