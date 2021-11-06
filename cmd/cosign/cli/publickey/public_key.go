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
		s, err := sigs.SignerFromKeyRef(ctx, opts.KeyRef, pf)
		if err != nil {
			return err
		}
		pkcs11Key, ok := s.(*pkcs11key.Key)
		if ok {
			defer pkcs11Key.Close()
		}
		k = s
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
