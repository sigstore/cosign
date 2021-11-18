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
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/sigstore/cosign/pkg/cosign/git"
	"github.com/sigstore/cosign/pkg/cosign/git/github"
	"github.com/sigstore/cosign/pkg/cosign/git/gitlab"
	"golang.org/x/term"

	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/kubernetes"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature/kms"
)

var (
	// Read is for fuzzing
	Read = readPasswordFn
)

// nolint
func GenerateKeyPairCmd(ctx context.Context, kmsVal string, name string, args []string) error {
	if kmsVal != "" {
		k, err := kms.Get(ctx, kmsVal, crypto.SHA256)
		if err != nil {
			return err
		}
		pubKey, err := k.CreateKey(ctx, k.DefaultAlgorithm())
		if err != nil {
			return errors.Wrap(err, "creating key")
		}
		pemBytes, err := cryptoutils.MarshalPublicKeyToPEM(pubKey)
		if err != nil {
			return err
		}
		if err := os.WriteFile(name+".pub", pemBytes, 0600); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "Public key written to "+name+".pub")
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

	if fileExists(name + ".key") {
		var overwrite string
		fmt.Fprint(os.Stderr, "File "+name+".key already exists. Overwrite (y/n)? ")
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
	if err := os.WriteFile(name+".key", keys.PrivateBytes, 0600); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Private key written to "+name+".key")

	if err := os.WriteFile(name+".pub", keys.PublicBytes, 0644); err != nil {
		return err
	} // #nosec G306
	fmt.Fprintln(os.Stderr, "Public key written to "+name+".pub")
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
	case isTerminal():
		return func() ([]byte, error) {
			return getPassFromTerm(confirm)
		}
	// Handle piped in passwords.
	default:
		return func() ([]byte, error) {
			return io.ReadAll(os.Stdin)
		}
	}
}

func isTerminal() bool {
	stat, _ := os.Stdin.Stat()
	return (stat.Mode() & os.ModeCharDevice) != 0
}

func getPassFromTerm(confirm bool) ([]byte, error) {
	fmt.Fprint(os.Stderr, "Enter password for private key: ")
	pw1, err := term.ReadPassword(0)
	if err != nil {
		return nil, err
	}
	if !confirm {
		return pw1, nil
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprint(os.Stderr, "Enter password for private key again: ")
	pw2, err := term.ReadPassword(0)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}

	if string(pw1) != string(pw2) {
		return nil, errors.New("passwords do not match")
	}
	return pw1, nil
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
