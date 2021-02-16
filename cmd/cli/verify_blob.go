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

func VerifyBlobCmd(_ context.Context, keyRef string, sigRef string, blobRef string) error {
	pubKey, err := cosign.LoadPublicKey(keyRef)
	if err != nil {
		return err
	}

	var b64SigBytes []byte
	// This can be the raw bytes or a path to them.
	if _, err = os.Stat(sigRef); os.IsNotExist(err) {
		b64SigBytes = []byte(sigRef)
	} else {
		b64SigBytes, err = ioutil.ReadFile(sigRef)
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

	if err := cosign.Verify(pubKey, string(b64SigBytes), blobBytes); err != nil {
		return err
	}
	fmt.Println("Verified OK")
	return nil
}
