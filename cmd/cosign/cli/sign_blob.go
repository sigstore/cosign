// Copyright 2021 The Rekor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
		ShortHelp:  `Sign the supplied blob, outputting the base64-encoded signature to stdout.`,
		LongHelp: `Sign the supplied blob, outputting the base64-encoded signature to stdout.

EXAMPLES
  # sign a blob with Google sign-in (experimental)
  COSIGN_EXPERIMENTAL=1 cosign sign-blob <FILE>

  # sign a blob with a local key pair file
  cosign sign-blob -key cosign.pub <FILE>

  # sign a blob with a key pair stored in Google Cloud KMS
  cosign sign-blob -kms gcpkms://projects/<PROJECT>/locations/global/keyRings/<KEYRING>/cryptoKeys/<KEY> <FILE>`,
		FlagSet: flagset,
		Exec: func(ctx context.Context, args []string) error {
			// A key file is required unless we're in experimental mode!
			if !cosign.Experimental() {
				if *key == "" && *kmsVal == "" {
					return &KeyParseError{}
				}
			}

			if len(args) == 0 {
				return flag.ErrHelp
			}
			for _, blob := range args {
				if _, err := SignBlobCmd(ctx, *key, *kmsVal, blob, *b64, GetPass); err != nil {
					return errors.Wrapf(err, "signing %s", blob)
				}
			}
			return nil
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
	var pemBytes []byte

	switch {
	case keyPath != "":
		var pub *ecdsa.PublicKey
		signature, pub, err = sign(ctx, keyPath, payload, pf)
		if err != nil {
			return nil, errors.Wrap(err, "signing blob")
		}
		pemBytes = cosign.KeyToPem(pub)
	case kmsVal != "":
		k, err := kms.Get(ctx, kmsVal)
		if err != nil {
			return nil, err
		}
		signature, err = k.Sign(ctx, payload)
		if err != nil {
			return nil, errors.Wrap(err, "signing")
		}
		publicKey, err := k.PublicKey(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "getting public key")
		}
		pemBytes = cosign.KeyToPem(publicKey)
	default: // Keyless!
		fmt.Fprintln(os.Stderr, "Generating ephemeral keys...")
		priv, err := cosign.GeneratePrivateKey()
		if err != nil {
			return nil, errors.Wrap(err, "generating cert")
		}
		fmt.Fprintln(os.Stderr, "Retrieving signed certificate...")
		pemBytes, _, err := fulcio.GetCert(ctx, priv) // TODO: use the chain
		if err != nil {
			return nil, errors.Wrap(err, "retrieving cert")
		}
		fmt.Fprintf(os.Stderr, "Signing with certificate:\n%s\n", string(pemBytes))
	}

	if cosign.Experimental() {
		index, err := cosign.UploadTLog(signature, payload, pemBytes)
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

func sign(ctx context.Context, keyPath string, payload []byte, pf cosign.PassFunc) (signature []byte, publicKey *ecdsa.PublicKey, err error) {
	k, err := loadKey(keyPath, pf)
	if err != nil {
		return nil, nil, err
	}
	publicKey = &k.Key.PublicKey
	signature, err = k.Sign(ctx, payload)
	if err != nil {
		return nil, nil, err
	}
	return signature, publicKey, nil
}
