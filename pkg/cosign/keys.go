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

package cosign

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"

	"github.com/pkg/errors"
	"github.com/theupdateframework/go-tuf/encrypted"
)

type PassFunc func(bool) ([]byte, error)

type Keys struct {
	PrivateBytes []byte
	PublicBytes  []byte
}

func GeneratePrivateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func GenerateKeyPair(pf PassFunc) (*Keys, error) {
	priv, err := GeneratePrivateKey()
	if err != nil {
		return nil, err
	}

	x509Encoded, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, errors.Wrap(err, "x509 encoding private key")
	}
	// Encrypt the private key and store it.
	password, err := pf(true)
	if err != nil {
		return nil, err
	}
	encBytes, err := encrypted.Encrypt(x509Encoded, password)
	if err != nil {
		return nil, err
	}
	// store in PEM format

	privBytes := pem.EncodeToMemory(&pem.Block{
		Bytes: encBytes,
		Type:  "ENCRYPTED COSIGN PRIVATE KEY",
	})

	// Now do the public key
	pubBytes, err := KeyToPem(&priv.PublicKey)
	if err != nil {
		return nil, err
	}

	return &Keys{
		PrivateBytes: privBytes,
		PublicBytes:  pubBytes,
	}, nil
}

type PublicKeyProvider interface {
	PublicKey(context.Context) (crypto.PublicKey, error)
}

func PublicKeyPem(ctx context.Context, key PublicKeyProvider) ([]byte, error) {
	pub, err := key.PublicKey(ctx)
	if err != nil {
		return nil, err
	}
	return KeyToPem(pub)
}

func KeyToPem(pub crypto.PublicKey) ([]byte, error) {
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: b,
	}), nil
}

func CertToPem(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.Raw,
	})
}

type ECDSAPublicKey struct {
	Key *ecdsa.PublicKey
}

type ECDSAKey struct {
	ECDSAPublicKey
	Key *ecdsa.PrivateKey
}

// Sign returns an ASN.1-encoded signature of the SHA-256 hash of the given payload.
func (k *ECDSAKey) Sign(_ context.Context, payload []byte) (signature []byte, err error) {
	h := sha256.Sum256(payload)
	return ecdsa.SignASN1(rand.Reader, k.Key, h[:])
}

func (k *ECDSAPublicKey) Verify(_ context.Context, payload, signature []byte) error {
	h := sha256.Sum256(payload)
	if !ecdsa.VerifyASN1(k.Key, h[:], signature) {
		return errors.New("unable to verify signature")
	}
	return nil
}

func (k *ECDSAPublicKey) PublicKey(_ context.Context) (crypto.PublicKey, error) {
	return k.Key, nil
}

func WithECDSAKey(key *ecdsa.PrivateKey) *ECDSAKey {
	return &ECDSAKey{
		ECDSAPublicKey: ECDSAPublicKey{Key: &key.PublicKey},
		Key:            key,
	}
}
