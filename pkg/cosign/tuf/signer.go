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
	"crypto"
	"encoding/json"
	"io"

	"github.com/sigstore/sigstore/pkg/signature"
)

const (
	KeyTypeFulcio   = "sigstore-oidc"
	KeySchemeFulcio = "https://fulcio.sigstore.dev"
)

var (
	KeyAlgorithms = []string{"sha256", "sha512"}
)

type FulcioKeyVal struct {
	Identity string `json:"identity"`
	Issuer   string `json:"issuer"`
}

func FulcioVerificationKey(email string, issuer string) *Key {
	keyValBytes, _ := json.Marshal(FulcioKeyVal{Identity: email, Issuer: issuer})
	return &Key{
		Type:       KeyTypeFulcio,
		Scheme:     KeySchemeFulcio,
		Algorithms: KeyAlgorithms,
		Value:      keyValBytes,
	}
}

// Implements Fulcio signer
type FulcioSigner struct {
	signature.Signer

	cert     string
	identity string
	issuer   string
}

func (s *FulcioSigner) PublicData() *Key {
	return FulcioVerificationKey(s.identity, s.issuer)
}

func (s *FulcioSigner) Type() string {
	return KeyTypeFulcio
}

func (s *FulcioSigner) Scheme() string {
	return KeySchemeFulcio
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

func Sign(s *Signed, key *FulcioSigner) (*Signed, error) {
	// Check if valid key
	publicKey := FulcioVerificationKey(key.identity, key.issuer)

	// Sign
	sig, err := key.SignMessage(bytes.NewReader(s.Signed))
	if err != nil {
		return nil, err
	}

	// Add or update signature.
	signatures := make([]Signature, 0, len(s.Signatures)+1)
	for _, signature := range s.Signatures {
		if publicKey.ID() != signature.KeyID {
			signatures = append(signatures, signature)
		}
	}
	signatures = append(signatures, Signature{KeyID: publicKey.ID(),
		Cert:      key.cert,
		Signature: string(sig)})
	s.Signatures = signatures

	return s, nil
}
