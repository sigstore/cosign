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
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/peterbourgon/ff/v3/ffcli"

	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/sigstore/pkg/kms"
)

type NamedWriter struct {
	Name string
	io.Writer
}

func PublicKey() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign public-key", flag.ExitOnError)
		key     = flagset.String("key", "", "path to the private key")
		kmsVal  = flagset.String("kms", "", "sign via a private key stored in a KMS")
		outFile = flagset.String("outfile", "", "file to write public key")
	)

	return &ffcli.Command{
		Name:       "public-key",
		ShortUsage: "cosign public-key gets a public key from the key-pair [-kms KMSPATH]",
		ShortHelp:  "public-key gets a public key from the key-pair",
		LongHelp: `public-key gets a public key from the key-pair and
writes to a specified file. By default, it will write to standard out.

EXAMPLES
  # extract public key from private key to a specified out file.
  cosign public-key -key <PRIVATE KEY FILE> -outfile <OUTPUT>

  # extract public key from Google Cloud KMS key pair
  cosign public-key -kms gcpkms://projects/<PROJECT>/locations/global/keyRings/<KEYRING>/cryptoKeys/<KEY>`,
		FlagSet: flagset,
		Exec: func(ctx context.Context, args []string) error {
			if !oneOf(*key, *kmsVal) {
				return &KeyParseError{}
			}
			// Get private key file.
			var reader io.Reader
			if *key != "" {
				cl := filepath.Clean(*key)
				var err error
				reader, err = os.Open(cl)
				if err != nil {
					return err
				}
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
			return GetPublicKey(ctx, reader, *kmsVal, writer, GetPass)
		},
	}
}

func GetPublicKey(ctx context.Context, reader io.Reader, kmsVal string, writer NamedWriter, pf cosign.PassFunc) error {
	var pemBytes []byte
	if kmsVal != "" {
		k, err := kms.Get(ctx, kmsVal)
		if err != nil {
			return err
		}
		pemBytes, err = cosign.PublicKeyPem(ctx, k)
		if err != nil {
			return err
		}
	} else {
		kb, err := ioutil.ReadAll(reader)
		if err != nil {
			return err
		}
		pass, err := pf(false)
		if err != nil {
			return nil
		}
		pk, err := cosign.LoadECDSAPrivateKey(kb, pass)
		if err != nil {
			return err
		}
		pemBytes, err = cosign.PublicKeyPem(ctx, pk)
		if err != nil {
			return err
		}
	}
	if _, err := writer.Write(pemBytes); err != nil {
		return err
	}
	if writer.Name != "" {
		fmt.Fprintln(os.Stderr, "Public key written to ", writer.Name)
	}
	return nil
}
