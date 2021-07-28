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
	"bytes"
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/sigstore/sigstore/pkg/signature/options"

	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/pkg/errors"

	"github.com/sigstore/cosign/pkg/cosign"
	rekorClient "github.com/sigstore/rekor/pkg/client"
)

func SignBlob() *ffcli.Command {
	var (
		flagset          = flag.NewFlagSet("cosign sign-blob", flag.ExitOnError)
		key              = flagset.String("key", "", "path to the private key file or a KMS URI")
		b64              = flagset.Bool("b64", true, "whether to base64 encode the output")
		sk               = flagset.Bool("sk", false, "whether to use a hardware security key")
		slot             = flagset.String("slot", "", "security key slot to use for generated key (default: signature) (authentication|signature|card-authentication|key-management)")
		fulcioURL        = flagset.String("fulcio-url", "https://fulcio.sigstore.dev", "[EXPERIMENTAL] address of sigstore PKI server")
		rekorURL         = flagset.String("rekor-url", "https://rekor.sigstore.dev", "[EXPERIMENTAL] address of rekor STL server")
		idToken          = flagset.String("identity-token", "", "[EXPERIMENTAL] identity token to use for certificate from fulcio")
		oidcIssuer       = flagset.String("oidc-issuer", "https://oauth2.sigstore.dev/auth", "[EXPERIMENTAL] OIDC provider to be used to issue ID token")
		oidcClientID     = flagset.String("oidc-client-id", "sigstore", "[EXPERIMENTAL] OIDC client ID for application")
		oidcClientSecret = flagset.String("oidc-client-secret", "", "[EXPERIMENTAL] OIDC client secret for application")
		output           = flagset.String("output", "", "write the signature to FILE")
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

  # sign a blob with a key pair stored in Azure Key Vault
  cosign sign-blob -key azurekms://[VAULT_NAME][VAULT_URI]/[KEY] <FILE>

  # sign a blob with a key pair stored in AWS KMS
  cosign sign-blob -key awskms://[ENDPOINT]/[ID/ALIAS/ARN] <FILE>

  # sign a blob with a key pair stored in Google Cloud KMS
  cosign sign-blob -key gcpkms://projects/[PROJECT]/locations/global/keyRings/[KEYRING]/cryptoKeys/[KEY] <FILE>

  # sign a blob with a key pair stored in Hashicorp Vault
  cosign sign-blob -key hashivault://[KEY] <FILE>`,
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
				KeyRef:           *key,
				Sk:               *sk,
				Slot:             *slot,
				PassFunc:         GetPass,
				FulcioURL:        *fulcioURL,
				RekorURL:         *rekorURL,
				IDToken:          *idToken,
				OIDCIssuer:       *oidcIssuer,
				OIDCClientID:     *oidcClientID,
				OIDCClientSecret: *oidcClientSecret,
			}
			for _, blob := range args {
				if _, err := SignBlobCmd(ctx, ko, blob, *b64, *output); err != nil {
					return errors.Wrapf(err, "signing %s", blob)
				}
			}
			return nil
		},
	}
}

type KeyOpts struct {
	Sk               bool
	Slot             string
	KeyRef           string
	FulcioURL        string
	RekorURL         string
	IDToken          string
	PassFunc         cosign.PassFunc
	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string
}

func SignBlobCmd(ctx context.Context, ko KeyOpts, payloadPath string, b64 bool, output string) ([]byte, error) {
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

	sv, err := signerFromKeyOpts(ctx, "", ko)
	if err != nil {
		return nil, err
	}

	sig, err := sv.SignMessage(bytes.NewReader(payload), options.WithContext(ctx))
	if err != nil {
		return nil, errors.Wrap(err, "signing blob")
	}

	if EnableExperimental() {
		// TODO: Refactor with sign.go
		rekorBytes := sv.Cert
		if rekorBytes == nil {
			pemBytes, err := publicKeyPem(sv, options.WithContext(ctx))
			if err != nil {
				return nil, err
			}
			rekorBytes = pemBytes
		}
		rekorClient, err := rekorClient.GetRekorClient(ko.RekorURL)
		if err != nil {
			return nil, err
		}
		entry, err := cosign.TLogUpload(rekorClient, sig, payload, rekorBytes)
		if err != nil {
			return nil, err
		}
		fmt.Println("tlog entry created with index:", *entry.LogIndex)
		return sig, nil
	}

	if output != "" {
		f, err := os.Create(output)
		if err != nil {
			return nil, err
		}
		defer f.Close()

		if b64 {
			_, err = f.Write([]byte(base64.StdEncoding.EncodeToString(sig)))
			if err != nil {
				return nil, err
			}
		} else {
			_, err = f.Write(sig)
			if err != nil {
				return nil, err
			}
		}

		fmt.Printf("Signature wrote in the file %s\n", f.Name())
	} else {
		if b64 {
			sig = []byte(base64.StdEncoding.EncodeToString(sig))
			fmt.Println(string(sig))
		} else if _, err := os.Stdout.Write(sig); err != nil {
			// No newline if using the raw signature
			return nil, err
		}
	}

	return sig, nil
}
