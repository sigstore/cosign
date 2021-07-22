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

package tuf

import (
	"bytes"
	"context"
	"crypto"
	"encoding/hex"
	"io"
	"strings"

	"github.com/pkg/errors"

	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/fulcio"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/data"
)

const (
	KeyTypeFulcio   = "sigstore-oidc"
	KeySchemeFulcio = "https://fulcio.sigstore.dev"
)

func FulcioVerificationKey(email string) *data.Key {
	return &data.Key{
		Type:       KeyTypeFulcio,
		Scheme:     KeySchemeFulcio,
		Algorithms: data.KeyAlgorithms,
		// TODO: Add issuer. Make KeyValue a more general map.
		Value: data.KeyValue{Public: []byte(hex.EncodeToString([]byte(email)))},
	}
}

// Implements Fulcio signer
type FulcioSigner struct {
	signature.Signer

	cert          string
	keyType       string
	keyScheme     string
	keyAlgorithms []string
	ids           []string
}

func GenerateFulcioSigner(ctx context.Context, idToken string) (*FulcioSigner, error) {
	k, err := fulcio.NewSigner(ctx, idToken)
	if err != nil {
		return nil, errors.Wrap(err, "getting key from Fulcio")
	}
	certs, err := cosign.LoadCerts(k.Cert)
	if err != nil {
		return nil, errors.Wrap(err, "getting Fulcio certificate")
	}

	return &FulcioSigner{
		Signer:        k,
		ids:           []string{certs[0].EmailAddresses[0]},
		cert:          k.Cert,
		keyType:       KeyTypeFulcio,
		keyScheme:     KeySchemeFulcio,
		keyAlgorithms: data.KeyAlgorithms,
	}, nil
}

func (s *FulcioSigner) PublicData() *data.Key {
	return FulcioVerificationKey(s.ids[0])
}

func (s *FulcioSigner) IDs() []string {
	return s.PublicData().IDs()
}

func (s *FulcioSigner) ContainsID(id string) bool {
	return strings.EqualFold(s.ids[0], id)
}

func (s *FulcioSigner) Type() string {
	return s.keyType
}

func (s *FulcioSigner) Scheme() string {
	return s.keyScheme
}

func (s *FulcioSigner) Cert() string {
	// PEM encoded, new lines escaped
	return s.cert
}

func (s *FulcioSigner) Public() crypto.PublicKey {
	pk, _ := s.Signer.PublicKey()
	return pk
}

func (s *FulcioSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return s.Signer.SignMessage(bytes.NewReader(digest))
}
