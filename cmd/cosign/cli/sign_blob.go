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
	"github.com/sigstore/cosign/pkg/cosign/kms"
)

func SignBlob() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign sign-blob", flag.ExitOnError)
		key     = flagset.String("key", "", "path to the private key")
		kmsVal  = flagset.String("kms", "", "sign via a private key stored in a KMS")
		b64     = flagset.Bool("b64", true, "whether to base64 encode the output")
	)
	return &ffcli.Command{
		Name:       "sign-blob",
		ShortUsage: "cosign sign-blob -key <key>|-kms <kms> [-sig <sig path>] <blob>",
		ShortHelp:  "Sign the supplied blob, outputting the base64-nocded signature to stdout",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			// A key file is required unless we're in experimental mode!
			if !cosign.Experimental() {
				if *key == "" && *kmsVal == "" {
					return flag.ErrHelp
				}
			}

			if len(args) != 1 {
				return flag.ErrHelp
			}

			_, err := SignBlobCmd(ctx, *key, *kmsVal, args[0], *b64, GetPass)
			return err
		},
	}
}

func SignBlobCmd(ctx context.Context, keyPath, kmsVal, payloadPath string, b64 bool, pf cosign.PassFunc) ([]byte, error) {
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

	var signature []byte
	var publicKey *ecdsa.PublicKey

	switch {
	case keyPath != "":
		signature, publicKey, err = sign(ctx, keyPath, payload, pf)
		if err != nil {
			return nil, errors.Wrap(err, "signing blob")
		}
	case kmsVal != "":
		k, err := kms.Get(ctx, kmsVal)
		if err != nil {
			return nil, err
		}
		signature, err = k.Sign(ctx, payload)
		if err != nil {
			return nil, errors.Wrap(err, "signing")
		}
		publicKey, err = k.PublicKey(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "getting public key")
		}
	default: // Keyless!
		fmt.Fprintln(os.Stderr, "Generating ephemeral keys...")
		priv, err := cosign.GeneratePrivateKey()
		if err != nil {
			return nil, errors.Wrap(err, "generating cert")
		}
		fmt.Fprintln(os.Stderr, "Retrieving signed certificate...")
		cert, _, err := fulcio.GetCert(ctx, priv) // TODO: use the chain
		if err != nil {
			return nil, errors.Wrap(err, "retrieving cert")
		}
		publicKey = &priv.PublicKey
		fmt.Fprintf(os.Stderr, "Signing with certificate:\n%s\n", cert)
	}

	if cosign.Experimental() {
		index, err := cosign.UploadTLog(signature, payload, publicKey)
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
