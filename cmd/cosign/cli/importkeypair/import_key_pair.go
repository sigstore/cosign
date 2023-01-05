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

package importkeypair

import (
	"context"
	"fmt"
	"io"
	"os"

	icos "github.com/sigstore/cosign/v2/internal/pkg/cosign"
	"github.com/sigstore/cosign/v2/internal/ui"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/env"
)

var (
	// Read is for fuzzing
	Read = readPasswordFn
)

// nolint
func ImportKeyPairCmd(ctx context.Context, keyVal string, outputKeyPrefixVal string, args []string) error {
	keys, err := cosign.ImportKeyPair(keyVal, GetPass)
	if err != nil {
		return err
	}

	privateKeyFileName := outputKeyPrefixVal + ".key"
	publicKeyFileName := outputKeyPrefixVal + ".pub"

	fileExists, err := icos.FileExists(privateKeyFileName)
	if err != nil {
		return fmt.Errorf("failed checking if %s exists: %w", privateKeyFileName, err)
	}

	if fileExists {
		ui.Warn(ctx, "File %s already exists. Overwrite?", privateKeyFileName)
		if err := ui.ConfirmContinue(ctx); err != nil {
			return err
		}
	}
	// TODO: make sure the perms are locked down first.
	if err := os.WriteFile(privateKeyFileName, keys.PrivateBytes, 0600); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Private key written to", privateKeyFileName)

	if err := os.WriteFile(publicKeyFileName, keys.PublicBytes, 0644); err != nil {
		return err
	} // #nosec G306
	fmt.Fprintln(os.Stderr, "Public key written to", publicKeyFileName)
	return nil
}

func GetPass(confirm bool) ([]byte, error) {
	read := Read(confirm)
	return read()
}

func readPasswordFn(confirm bool) func() ([]byte, error) {
	pw, ok := env.LookupEnv(env.VariablePassword)
	switch {
	case ok:
		return func() ([]byte, error) {
			return []byte(pw), nil
		}
	case cosign.IsTerminal():
		return func() ([]byte, error) {
			return cosign.GetPassFromTerm(confirm)
		}
	// Handle piped in passwords.
	default:
		return func() ([]byte, error) {
			return io.ReadAll(os.Stdin)
		}
	}
}
