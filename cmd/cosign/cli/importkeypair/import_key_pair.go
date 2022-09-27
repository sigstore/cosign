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

	icos "github.com/sigstore/cosign/internal/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign"
)

var (
	// Read is for fuzzing
	Read = readPasswordFn
)

// nolint
func ImportKeyPairCmd(ctx context.Context, keyVal string, args []string) error {
	keys, err := cosign.ImportKeyPair(keyVal, GetPass)
	if err != nil {
		return err
	}

	fileExists, err := icos.FileExists("import-cosign.key")
	if err != nil {
		return fmt.Errorf("failed checking if import-cosign.key exists: %w", err)
	}

	if fileExists {
		var overwrite string
		fmt.Fprint(os.Stderr, "File import-cosign.key already exists. Overwrite (y/n)? ")
		fmt.Scanf("%s", &overwrite)
		switch overwrite {
		case "y", "Y":
		case "n", "N":
			return nil
		default:
			fmt.Fprintln(os.Stderr, "Invalid input")
			return nil
		}
	}
	// TODO: make sure the perms are locked down first.
	if err := os.WriteFile("import-cosign.key", keys.PrivateBytes, 0600); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Private key written to import-cosign.key")

	if err := os.WriteFile("import-cosign.pub", keys.PublicBytes, 0644); err != nil {
		return err
	} // #nosec G306
	fmt.Fprintln(os.Stderr, "Public key written to import-cosign.pub")
	return nil
}

func GetPass(confirm bool) ([]byte, error) {
	read := Read(confirm)
	return read()
}

func readPasswordFn(confirm bool) func() ([]byte, error) {
	pw, ok := os.LookupEnv("COSIGN_PASSWORD")
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
