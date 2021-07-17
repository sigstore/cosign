// +build pivkey
// +build cgo

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

package pivkey

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"io"

	"github.com/sigstore/sigstore/pkg/signature"
)

type ECSignerVerifier struct {
	Priv crypto.PrivateKey
	Pub  crypto.PrivateKey
	*signature.ECDSAVerifier
}

func (s *ECSignerVerifier) Sign(ctx context.Context, rawPayload []byte) ([]byte, []byte, error) {
	signer := s.Priv.(crypto.Signer)
	h := sha256.Sum256(rawPayload)
	sig, err := signer.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		return nil, nil, err
	}
	return sig, h[:], err
}

func (s *ECSignerVerifier) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	signer := s.Priv.(crypto.Signer)

	h := sha256.New()
	if _, err := io.Copy(h, message); err != nil {
		return nil, err
	}
	sig, err := signer.Sign(rand.Reader, h.Sum(nil), crypto.SHA256)
	if err != nil {
		return nil, err
	}
	return sig, err
}

func (s *ECSignerVerifier) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return s.Pub, nil
}

var _ signature.Signer = &ECSignerVerifier{}
