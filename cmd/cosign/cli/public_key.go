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
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/pkg/errors"

	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/pivkey"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

type NamedWriter struct {
	Name string
	io.Writer
}

func PublicKey() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign public-key", flag.ExitOnError)
		key     = flagset.String("key", "", "path to the private key file, public key URL, or KMS URI")
		sk      = flagset.Bool("sk", false, "whether to use a hardware security key")
		slot    = flagset.String("slot", "", "security key slot to use for generated key (default: signature) (authentication|signature|card-authentication|key-management)")
		outFile = flagset.String("outfile", "", "file to write public key")
	)

	return &ffcli.Command{
		Name:       "public-key",
		ShortUsage: "cosign public-key gets a public key from the key-pair",
		ShortHelp:  "Gets a public key from the key-pair",
		LongHelp: `Gets a public key from the key-pair and
writes to a specified file. By default, it will write to standard out.

EXAMPLES
  # extract public key from private key to a specified out file.
  cosign public-key -key <PRIVATE KEY FILE> -outfile <OUTPUT>

  # extract public key from URL.
  cosign public-key -key https://host.for/<FILE> -outfile <OUTPUT>

  # extract public key from Azure Key Vault
  cosign public-key -key azurekms://[VAULT_NAME][VAULT_URI]/[KEY]

  # extract public key from AWS KMS
  cosign public-key -key awskms://[ENDPOINT]/[ID/ALIAS/ARN]

  # extract public key from Google Cloud KMS
  cosign public-key -key gcpkms://projects/[PROJECT]/locations/global/keyRings/[KEYRING]/cryptoKeys/[KEY]

  # extract public key from Hashicorp Vault KMS
  cosign public-key -key hashivault://[KEY]`,
		FlagSet: flagset,
		Exec: func(ctx context.Context, args []string) error {

			if !oneOf(*key, *sk) {
				return &KeyParseError{}
			}

			writer := NamedWriter{Name: "", Writer: nil}
			var f *os.File
			// Open output file for public key if specified.
			if *outFile != "" {
				writer.Name = *outFile
				var err error
				f, err = os.OpenFile(*outFile, os.O_WRONLY|os.O_CREATE, 0600)
				if err != nil {
					return err
				}
				writer.Writer = f
				defer f.Close()
			} else {
				writer.Writer = os.Stdout
			}
			pk := Pkopts{
				KeyRef: *key,
				Sk:     *sk,
				Slot:   *slot,
			}
			return GetPublicKey(ctx, pk, writer, GetPass)
		},
	}
}

type Pkopts struct {
	KeyRef string
	Sk     bool
	Slot   string
}

func GetPublicKey(ctx context.Context, opts Pkopts, writer NamedWriter, pf cosign.PassFunc) error {
	var k signature.PublicKeyProvider
	switch {
	case opts.KeyRef != "":
		s, err := signerFromKeyRef(ctx, opts.KeyRef, pf)
		if err != nil {
			return err
		}
		k = s
	case opts.Sk:
		sk, err := pivkey.GetKeyWithSlot(opts.Slot)
		if err != nil {
			return errors.Wrap(err, "opening piv token")
		}
		defer sk.Close()
		pk, err := sk.Verifier()
		if err != nil {
			return errors.Wrap(err, "initializing piv token verifier")
		}
		k = pk
	}

	pemBytes, err := publicKeyPem(k, options.WithContext(ctx))
	if err != nil {
		return err
	}

	if _, err := writer.Write(pemBytes); err != nil {
		return err
	}
	if writer.Name != "" {
		fmt.Fprintln(os.Stderr, "Public key written to ", writer.Name)
	}
	return nil
}
