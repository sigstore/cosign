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
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/sigstore/rekor/cmd/rekor-cli/app"
	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/pkg/errors"

	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/fulcio"
	"github.com/sigstore/cosign/pkg/cosign/pivkey"
)

func SignBlob() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign sign-blob", flag.ExitOnError)
		key     = flagset.String("key", "", "path to the private key file or a KMS URI")
		b64     = flagset.Bool("b64", true, "whether to base64 encode the output")
		sk      = flagset.Bool("sk", false, "whether to use a hardware security key")
		idToken = flagset.String("identity-token", "", "[EXPERIMENTAL] identity token to use for certificate from fulcio")
	)
	return &ffcli.Command{
		Name:       "sign-blob",
		ShortUsage: "cosign sign-blob -key <key path>|<kms uri> [-sig <sig path>] <blob>",
		ShortHelp:  `Sign the supplied blob, outputting the base64-encoded signature to stdout.`,
		LongHelp: `Sign the supplied blob, outputting the base64-encoded signature to stdout.

EXAMPLES
  # sign a blob with Google sign-in (experimental)
  COSIGN_EXPERIMENTAL=1 cosign sign-blob <FILE>

  # sign a blob with a local key pair file
  cosign sign-blob -key cosign.key <FILE>

  # sign a blob with a key pair stored in Google Cloud KMS
  cosign sign-blob -key gcpkms://projects/<PROJECT>/locations/global/keyRings/<KEYRING>/cryptoKeys/<KEY> <FILE>`,
		FlagSet: flagset,
		Exec: func(ctx context.Context, args []string) error {
			// A key file is required unless we're in experimental mode!
			if !EnableExperimental() {
				if !oneOf(*key, *sk) {
					return &KeyParseError{}
				}
			}

			if len(args) == 0 {
				return flag.ErrHelp
			}
			ko := KeyOpts{
				KeyRef: *key,
				Sk:     *sk,
			}
			for _, blob := range args {
				if _, err := SignBlobCmd(ctx, ko, blob, *b64, GetPass, *idToken); err != nil {
					return errors.Wrapf(err, "signing %s", blob)
				}
			}
			return nil
		},
	}
}

type KeyOpts struct {
	Sk     bool
	KeyRef string
}

func SignBlobCmd(ctx context.Context, ko KeyOpts, payloadPath string, b64 bool, pf cosign.PassFunc, idToken string) ([]byte, error) {
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

	var cert string
	var signer signature.Signer
	switch {
	case ko.KeyRef != "":
		k, err := signerFromKeyRef(ctx, ko.KeyRef, pf)
		if err != nil {
			return nil, errors.Wrap(err, "loading key")
		}
		signer = k
	case ko.Sk:
		k, err := pivkey.NewSignerVerifier()
		if err != nil {
			return nil, err
		}
		signer = k
	default:
		// Keyless!
		fmt.Fprintln(os.Stderr, "Generating ephemeral keys...")
		k, err := fulcio.NewSigner(ctx, idToken)
		if err != nil {
			return nil, errors.Wrap(err, "getting key from Fulcio")
		}
		signer = k
		cert = k.Cert
		fmt.Fprintf(os.Stderr, "Signing with certificate:\n%s\n", cert)
	}

	sig, _, err := signer.Sign(ctx, payload)
	if err != nil {
		return nil, errors.Wrap(err, "signing blob")
	}

	if EnableExperimental() {
		// TODO: Refactor with sign.go
		var rekorBytes []byte
		if cert != "" {
			rekorBytes = []byte(cert)
		} else {
			pemBytes, err := cosign.PublicKeyPem(ctx, signer)
			if err != nil {
				return nil, err
			}
			rekorBytes = pemBytes
		}
		rekorClient, err := app.GetRekorClient(TlogServer())
		if err != nil {
			return nil, err
		}
		entry, err := cosign.UploadTLog(rekorClient, sig, payload, rekorBytes)
		if err != nil {
			return nil, err
		}
		fmt.Println("tlog entry created with index:", *entry.LogIndex)
		return sig, nil
	}

	if b64 {
		sig = []byte(base64.StdEncoding.EncodeToString(sig))
		fmt.Println(string(sig))
	} else if _, err := os.Stdout.Write(sig); err != nil {
		// No newline if using the raw signature
		return nil, err
	}
	return sig, nil
}
