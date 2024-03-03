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

package generate

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/sigstore/cosign/v2/pkg/cosign/env"
	"github.com/sigstore/cosign/v2/pkg/cosign/git"
	"github.com/sigstore/cosign/v2/pkg/cosign/git/github"
	"github.com/sigstore/cosign/v2/pkg/cosign/git/gitlab"

	icos "github.com/sigstore/cosign/v2/internal/pkg/cosign"
	"github.com/sigstore/cosign/v2/internal/ui"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/kubernetes"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature/kms"
)

var (
	// Read is for fuzzing
	Read = readPasswordFn
)

// nolint
func GenerateKeyPairCmd(ctx context.Context, kmsVal string, outputKeyPrefixVal string, args []string) error {
	privateKeyFileName := outputKeyPrefixVal + ".key"
	publicKeyFileName := outputKeyPrefixVal + ".pub"

	if kmsVal != "" {
		k, err := kms.Get(ctx, kmsVal, crypto.SHA256)
		if err != nil {
			return err
		}
		pubKey, err := k.CreateKey(ctx, k.DefaultAlgorithm())
		if err != nil {
			return fmt.Errorf("creating key: %w", err)
		}
		pemBytes, err := cryptoutils.MarshalPublicKeyToPEM(pubKey)
		if err != nil {
			return err
		}
		if err := os.WriteFile(publicKeyFileName, pemBytes, 0600); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "Public key written to", publicKeyFileName)
		return nil
	}

	if len(args) > 0 {
		split := strings.Split(args[0], "://")

		if len(split) < 2 {
			return errors.New("could not parse scheme, use <scheme>://<ref> format")
		}

		provider, targetRef := split[0], split[1]

		switch provider {
		case "k8s":
			return kubernetes.KeyPairSecret(ctx, targetRef, GetPass)
		case gitlab.ReferenceScheme, github.ReferenceScheme:
			return git.GetProvider(provider).PutSecret(ctx, targetRef, GetPass)
		}

		return fmt.Errorf("undefined provider: %s", provider)
	}

	keys, err := cosign.GenerateKeyPair(GetPass)
	if err != nil {
		return err
	}

	fileExists, err := icos.FileExists(privateKeyFileName)
	if err != nil {
		return fmt.Errorf("failed checking if %s exists: %w", privateKeyFileName, err)
	}

	if fileExists {
		ui.Warnf(ctx, "File %s already exists. Overwrite?", privateKeyFileName)
		if err := ui.ConfirmContinue(ctx); err != nil {
			return err
		}
		return writeKeyFiles(privateKeyFileName, publicKeyFileName, keys)
	}

	return writeKeyFiles(privateKeyFileName, publicKeyFileName, keys)
}

func writeKeyFiles(privateKeyFileName string, publicKeyFileName string, keys *cosign.KeysBytes) error {
	// TODO: make sure the perms are locked down first.
	if err := os.WriteFile(privateKeyFileName, keys.PrivateBytes, 0600); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Private key written to", privateKeyFileName)

	if err := os.WriteFile(publicKeyFileName, keys.PublicBytes, 0644); err != nil { //nolint: gosec
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
