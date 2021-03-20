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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	pubBytes := KeyToPem(&priv.PublicKey)

	return &Keys{
		PrivateBytes: privBytes,
		PublicBytes:  pubBytes,
	}, nil
}

func KeyToPem(pub *ecdsa.PublicKey) []byte {
	// This can only panic if the key is not an actual crypto key, so we're safe
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: b,
	})
}

func CertToPem(c *x509.Certificate) []byte {
	// This can only panic if the key is not an actual crypto key, so we're safe
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.Raw,
	})
}
