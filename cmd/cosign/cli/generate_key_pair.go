/*
Copyright The Rekor Authors

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

package cli

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/kms"

	"github.com/peterbourgon/ff/v3/ffcli"
	"golang.org/x/term"
)

var (
	// Read is for fuzzing
	Read = readPasswordFn
)

func GenerateKeyPair() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign generate-key-pair", flag.ExitOnError)
		kmsVal  = flagset.String("kms", "", "create key pair in KMS service to use for signing")
	)

	return &ffcli.Command{
		Name:       "generate-key-pair",
		ShortUsage: "cosign generate-key-pair [-kms KMSPATH]",
		ShortHelp:  "generate-key-pair generates a key-pair",
		LongHelp:   "generate-key-pair generates a key-pair",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			return GenerateKeyPairCmd(ctx, *kmsVal)
		},
	}
}

func GenerateKeyPairCmd(ctx context.Context, kmsVal string) error {
	if kmsVal != "" {
		k, err := kms.Get(ctx, kmsVal)
		if err != nil {
			return err
		}
		pub, err := k.CreateKey(ctx)
		if err != nil {
			return err
		}
		derBytes, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return err
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: derBytes,
		})
		if err := ioutil.WriteFile("cosign.pub", pemBytes, 0600); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "Public key written to cosign.pub")
		return nil
	}

	keys, err := cosign.GenerateKeyPair(GetPass)
	if err != nil {
		return err
	}
	// TODO: make sure the perms are locked down first.
	if err := ioutil.WriteFile("cosign.key", keys.PrivateBytes, 0600); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Private key written to cosign.key")

	if err := ioutil.WriteFile("cosign.pub", keys.PublicBytes, 0600); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Public key written to cosign.pub")
	return nil
}

func GetPass(confirm bool) ([]byte, error) {
	read := Read()
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

func readPasswordFn() func() ([]byte, error) {
	// Handle piped in passwords.
	r := func() ([]byte, error) {
		return term.ReadPassword(0)
	}
	if !term.IsTerminal(0) {
		r = func() ([]byte, error) {
			return ioutil.ReadAll(os.Stdin)
		}
	}
	return r
}
