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

package cli

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/projectcosign/cosign/pkg/cosign"
)

func VerifyBlob() *ffcli.Command {
	var (
		flagset   = flag.NewFlagSet("cosign verify", flag.ExitOnError)
		key       = flagset.String("key", "", "path to the public key")
		signature = flagset.String("signature", "", "path to the signature")
	)
	return &ffcli.Command{
		Name:       "verify-blob",
		ShortUsage: "cosign verify -key <key> -signature <sig> <blob>",
		ShortHelp:  "Verify a signature on the supplied blob",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			if *key == "" {
				return flag.ErrHelp
			}
			if len(args) != 1 {
				return flag.ErrHelp
			}
			return VerifyBlobCmd(ctx, *key, *signature, args[0])
		},
	}
}

func isb64(data []byte) bool {
	_, err := base64.StdEncoding.DecodeString(string(data))
	return err == nil
}

func VerifyBlobCmd(_ context.Context, keyRef string, sigRef string, blobRef string) error {
	pubKey, err := cosign.LoadPublicKey(keyRef)
	if err != nil {
		return err
	}

	var b64sig string
	// This can be the base64-encoded bytes or a path to the signature
	if _, err = os.Stat(sigRef); os.IsNotExist(err) {
		b64sig = sigRef
	} else {
		b, err := ioutil.ReadFile(sigRef)
		if err != nil {
			return nil
		}
		// If in a file, it could be raw or base64-encoded.
		// We want them to be encoded eventually, but not double encoded!
		if isb64(b) {
			b64sig = string(b)
		} else {
			b64sig = base64.StdEncoding.EncodeToString(b)
		}
	}
	if err != nil {
		return err
	}

	var blobBytes []byte
	if blobRef == "-" {
		blobBytes, err = ioutil.ReadAll(os.Stdin)
	} else {
		blobBytes, err = ioutil.ReadFile(blobRef)
	}
	if err != nil {
		return err
	}

	if err := cosign.VerifySignature(pubKey, b64sig, blobBytes); err != nil {
		return err
	}
	fmt.Println("Verified OK")
	return nil
}
