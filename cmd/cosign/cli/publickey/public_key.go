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

package publickey

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/pkg/errors"

	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/pivkey"
	"github.com/sigstore/cosign/pkg/cosign/pkcs11key"
	sigs "github.com/sigstore/cosign/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
)

type NamedWriter struct {
	Name string
	io.Writer
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
		// If -key starts with pkcs11:, we assume it is a PKCS11 URI and use it to get the PKCS11 Key.
		if strings.HasPrefix(opts.KeyRef, "pkcs11:") {
			pkcs11UriConfig := pkcs11key.NewPkcs11UriConfig()
			err := pkcs11UriConfig.Parse(opts.KeyRef)
			if err != nil {
				return errors.Wrap(err, "parsing pkcs11 uri")
			}

			sk, err := pkcs11key.GetKeyWithUriConfig(pkcs11UriConfig, false)
			if err != nil {
				return errors.Wrap(err, "opening pkcs11 token key")
			}
			defer sk.Close()

			pk, err := sk.Verifier()
			if err != nil {
				return errors.Wrap(err, "initializing pkcs11 token verifier")
			}
			k = pk
		} else {
			s, err := sigs.SignerFromKeyRef(ctx, opts.KeyRef, pf)
			if err != nil {
				return err
			}
			k = s
		}
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

	pemBytes, err := sigs.PublicKeyPem(k, signatureoptions.WithContext(ctx))
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
