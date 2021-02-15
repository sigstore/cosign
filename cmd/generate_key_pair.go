/*
Copyright The Cosign Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/theupdateframework/go-tuf/encrypted"

	"github.com/peterbourgon/ff/v3/ffcli"
	"golang.org/x/term"
)

func GenerateKeyPair() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign generate-key-pair", flag.ExitOnError)
	)

	return &ffcli.Command{
		Name:       "generate-key-pair",
		ShortUsage: "cosign generate-key-pair",
		ShortHelp:  "generate-key-pair generates a key-pair",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			return generateKeyPair(ctx)
		},
	}
}

func generateKeyPair(ctx context.Context) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	// Encrypt the private key and store it.
	password, err := getPass(true)
	if err != nil {
		return err
	}

	encBytes, err := encrypted.Encrypt(priv, password)
	if err != nil {
		return err
	}

	privBytes := pem.EncodeToMemory(&pem.Block{
		Bytes: encBytes,
		Type:  "ENCRYPTED COSIGN PRIVATE KEY",
	})
	// TODO: make sure the perms are locked down first.
	if err := ioutil.WriteFile("cosign.key", privBytes, 0600); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Private key written to cosign.key")

	// Now do the public key
	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "COSIGN PUBLIC KEY",
		Bytes: pub,
	})
	if err := ioutil.WriteFile("cosign.pub", pubBytes, 0600); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Public key written to cosign.pub")
	return nil
}

func getPass(confirm bool) ([]byte, error) {
	// Handle piped in passwords.
	var read = func() ([]byte, error) {
		return term.ReadPassword(0)
	}
	if !term.IsTerminal(0) {
		read = func() ([]byte, error) {
			return ioutil.ReadAll(os.Stdin)
		}
	}
	fmt.Fprint(os.Stderr, "Enter password for private key: ")
	pw1, err := read()
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	if !confirm {
		return pw1, nil
	}
	fmt.Fprint(os.Stderr, "Enter again: ")
	pw2, err := read()
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}

	if string(pw1) != string(pw2) {
		return nil, errors.New("passwords do not match")
	}
	return pw1, nil
}
