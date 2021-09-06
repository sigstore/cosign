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

package cli

import (
	"context"
	"crypto"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/pkg/errors"
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

func GenerateKeyPair() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign generate-key-pair", flag.ExitOnError)
		kmsVal  = flagset.String("kms", "", "create key pair in KMS service to use for signing")
	)

	return &ffcli.Command{
		Name:       "generate-key-pair",
		ShortUsage: "cosign generate-key-pair [-kms KMSPATH]",
		ShortHelp:  "Generates a key-pair",
		LongHelp: `Generates a key-pair for signing.

EXAMPLES:
  # generate key-pair and write to cosign.key and cosign.pub files
  cosign generate-key-pair

  # generate a key-pair in Azure Key Vault
  cosign generate-key-pair -kms azurekms://[VAULT_NAME][VAULT_URI]/[KEY]

  # generate a key-pair in AWS KMS
  cosign generate-key-pair -kms awskms://[ENDPOINT]/[ID/ALIAS/ARN]

  # generate a key-pair in Google Cloud KMS
  cosign generate-key-pair -kms gcpkms://projects/[PROJECT]/locations/global/keyRings/[KEYRING]/cryptoKeys/[KEY]

  # generate a key-pair in Hashicorp Vault
  cosign generate-key-pair -kms hashivault://[KEY]

  # generate a key-pair in Kubernetes Secret
  cosign generate-key-pair k8s://[NAMESPACE]/[NAME]

CAVEATS:
  This command interactively prompts for a password. You can use
  the COSIGN_PASSWORD environment variable to provide one.`,
		FlagSet: flagset,
		Exec: func(ctx context.Context, args []string) error {
			return GenerateKeyPairCmd(ctx, *kmsVal, args)
		},
	}
}

func GenerateKeyPairCmd(ctx context.Context, kmsVal string, args []string) error {
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
		if err := ioutil.WriteFile("cosign.pub", pemBytes, 0600); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "Public key written to cosign.pub")
		return nil
	}
	if len(args) > 0 {
		return kubernetes.KeyPairSecret(ctx, args[0], GetPass)
	}

	keys, err := cosign.GenerateKeyPair(GetPass)
	if err != nil {
		return err
	}

	if fileExists("cosign.key") {
		var overwrite string
		fmt.Fprint(os.Stderr, "File cosign.key already exists. Overwrite (y/n)? ")
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
	if err := ioutil.WriteFile("cosign.key", keys.PrivateBytes, 0600); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Private key written to cosign.key")

	if err := ioutil.WriteFile("cosign.pub", keys.PublicBytes, 0644); err != nil {
		return err
	} // #nosec G306
	fmt.Fprintln(os.Stderr, "Public key written to cosign.pub")
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
	case term.IsTerminal(0):
		return func() ([]byte, error) {
			return getPassFromTerm(confirm)
		}
	// Handle piped in passwords.
	default:
		return func() ([]byte, error) {
			return ioutil.ReadAll(os.Stdin)
		}
	}
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
