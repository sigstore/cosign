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
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/fulcio"
)

func SignBlob() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign sign-blob", flag.ExitOnError)
		key     = flagset.String("key", "", "path to the private key")
		b64     = flagset.Bool("b64", true, "whether to base64 encode the output")
	)
	return &ffcli.Command{
		Name:       "sign-blob",
		ShortUsage: "cosign sign-blob -key <key> [-sig <sig path>] <blob>",
		ShortHelp:  "Sign the supplied blob, outputting the base64-nocded signature to stdout",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			// A key file is required unless we're in experimental mode!
			if !cosign.Experimental() {
				if *key == "" {
					return flag.ErrHelp
				}
			}

			if len(args) != 1 {
				return flag.ErrHelp
			}

			_, err := SignBlobCmd(ctx, *key, args[0], *b64, getPass)
			return err
		},
	}
}

func SignBlobCmd(ctx context.Context, keyPath, payloadPath string, b64 bool, pf cosign.PassFunc) ([]byte, error) {
	var payload []byte
	var err error
	if payloadPath == "-" {
		payload, err = ioutil.ReadAll(os.Stdin)
	} else {
		fmt.Fprintln(os.Stderr, "Using payload from:", payloadPath)
		payload, err = ioutil.ReadFile(filepath.Clean(payloadPath))
	}
	if err != nil {
		return nil, err
	}

	var priv *ecdsa.PrivateKey
	var cert string
	if keyPath != "" {
		kb, err := ioutil.ReadFile(filepath.Clean(keyPath))
		if err != nil {
			return nil, errors.Wrapf(err, "reading %s", keyPath)
		}
		pass, err := pf(false)
		if err != nil {
			return nil, err
		}
		priv, err = cosign.LoadPrivateKey(kb, pass)
		if err != nil {
			return nil, errors.Wrap(err, "loading private key")
		}
	} else { // Keyless!
		fmt.Fprintln(os.Stderr, "Generating ephemeral keys...")
		priv, err = cosign.GeneratePrivateKey()
		if err != nil {
			return nil, errors.Wrap(err, "generating cert")
		}
		fmt.Fprintln(os.Stderr, "Retrieving signed certificate...")
		cert, err = fulcio.GetCert(ctx, priv)
		if err != nil {
			return nil, errors.Wrap(err, "retrieving cert")
		}
		fmt.Fprintf(os.Stderr, "Signing with certificate:\n%s\n", cert)
	}
	h := sha256.Sum256(payload)
	signature, err := ecdsa.SignASN1(rand.Reader, priv, h[:])
	if err != nil {
		return nil, err
	}

	if cosign.Experimental() {
		index, err := cosign.UploadTLog(signature, payload, &priv.PublicKey)
		if err != nil {
			return nil, err
		}
		fmt.Println("tlog entry created with index: ", index)
		return signature, nil
	}

	if b64 {
		signature = []byte(base64.StdEncoding.EncodeToString(signature))
		fmt.Println(string(signature))
	} else {
		// No newline if using the raw signature
		_, err := os.Stdout.Write(signature)
		if err != nil {
			return nil, err
		}
	}

	return signature, nil
}
