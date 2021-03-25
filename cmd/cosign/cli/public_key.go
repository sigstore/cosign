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
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/go-piv/piv-go/piv"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/kms"

	"github.com/peterbourgon/ff/v3/ffcli"
)

func PublicKey() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign public-key", flag.ExitOnError)
		key     = flagset.String("key", "", "path to the private key")
		kmsVal  = flagset.String("kms", "", "sign via a private key stored in a KMS")
	)

	return &ffcli.Command{
		Name:       "public-key",
		ShortUsage: "cosign public-key gets a public key from the key-pair [-kms KMSPATH]",
		ShortHelp:  "public-key gets a public key from the key-pair",
		LongHelp: `public-key gets a public key from the key-pair and
writes to cosign.pub in the current directory.

EXAMPLES
  # extract public key from private key
  cosign public-key -key <PRIVATE KEY FILE>

  # extract public key from Google Cloud KMS key pair
  cosign public-key -kms gcpkms://projects/<PROJECT>/locations/global/keyRings/<KEYRING>/cryptoKeys/<KEY>`,
		FlagSet: flagset,
		Exec: func(ctx context.Context, args []string) error {
			if (*key == "" && *kmsVal == "") || (*key != "" && *kmsVal != "") {
				return &KeyParseError{}
			}
			return GetPublicKey(ctx, *key, *kmsVal, GetPass)
		},
	}
}

func GetPublicKey(ctx context.Context, keyPath, kmsVal string, pf cosign.PassFunc) error {
	var pub *ecdsa.PublicKey
	switch {
	case kmsVal != "":
		k, err := kms.Get(ctx, kmsVal)
		if err != nil {
			return err
		}
		pub, err = k.PublicKey(ctx)
		if err != nil {
			return err
		}
	case keyPath == "yubikey":
		yk, err := cosign.GetYubikey()
		if err != nil {
			return err
		}
		c, err := yk.Attest(piv.SlotSignature)
		if err != nil {
			return err
		}
		pub = c.PublicKey.(*ecdsa.PublicKey)
	default:
		cl := filepath.Clean(keyPath)
		if _, err := os.Stat(cl); os.IsNotExist(err) {
			return fmt.Errorf("missing or invalid key path: %s", cl)
		} else if err != nil {
			return err
		}
		kb, err := ioutil.ReadFile(cl)
		if err != nil {
			return err
		}
		pass, err := pf(false)
		if err != nil {
			return nil
		}
		pk, err := cosign.LoadPrivateKey(kb, pass)
		if err != nil {
			return err
		}
		pub = &pk.PublicKey
	}
	pemBytes, err := cosign.MarshalPublicKey(pub)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile("cosign.pub", pemBytes, 0600); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Public key written to cosign.pub")
	return nil
}
