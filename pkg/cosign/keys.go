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

package cosign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256" // for `crypto.SHA256`
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/theupdateframework/go-tuf/encrypted"

	"github.com/sigstore/cosign/pkg/oci/static"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

const (
	PrivateKeyPemType    = "ENCRYPTED COSIGN PRIVATE KEY"
	RSAPrivateKeyPemType = "RSA PRIVATE KEY"
	ECPrivateKeyPemType  = "EC PRIVATE KEY"
	BundleKey            = static.BundleAnnotationKey
)

type PassFunc func(bool) ([]byte, error)

type Keys struct {
	private crypto.PrivateKey
	public  crypto.PublicKey
}

type KeysBytes struct {
	PrivateBytes []byte
	PublicBytes  []byte
	password     []byte
}

func GeneratePrivateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func ImportKeyPair(keyPath string, pf PassFunc) (*KeysBytes, error) {

	kb, err := os.ReadFile(filepath.Clean(keyPath))
	if err != nil {
		return nil, err
	}

	p, _ := pem.Decode(kb)
	if p == nil {
		return nil, errors.New("invalid pem block")
	}

	switch p.Type {

	case RSAPrivateKeyPemType:
		pk, err := x509.ParsePKCS1PrivateKey(p.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing error")
		}
		return marshalKeyPair(Keys{pk, pk.Public()}, pf)
	default:
		pk, err := x509.ParseECPrivateKey(p.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing error")
		}
		return marshalKeyPair(Keys{pk, pk.Public()}, pf)
	}

}

func marshalKeyPair(keypair Keys, pf PassFunc) (*KeysBytes, error) {

	x509Encoded, err := x509.MarshalPKCS8PrivateKey(keypair.private)
	if err != nil {
		return nil, errors.Wrap(err, "x509 encoding private key")
	}

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
		Type:  PrivateKeyPemType,
	})

	// Now do the public key
	pubBytes, err := cryptoutils.MarshalPublicKeyToPEM(keypair.public)
	if err != nil {
		return nil, err
	}

	return &KeysBytes{
		PrivateBytes: privBytes,
		PublicBytes:  pubBytes,
		password:     password,
	}, nil
}

func GenerateKeyPair(pf PassFunc) (*KeysBytes, error) {
	priv, err := GeneratePrivateKey()
	if err != nil {
		return nil, err
	}

	return marshalKeyPair(Keys{priv, priv.Public()}, pf)
}

func (k *KeysBytes) Password() []byte {
	return k.password
}

func PemToECDSAKey(pemBytes []byte) (*ecdsa.PublicKey, error) {
	pub, err := cryptoutils.UnmarshalPEMToPublicKey(pemBytes)
	if err != nil {
		return nil, err
	}
	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid public key: was %T, require *ecdsa.PublicKey", pub)
	}
	return ecdsaPub, nil
}

func LoadPrivateKey(key []byte, pass []byte) (signature.SignerVerifier, error) {

	// Decrypt first
	p, _ := pem.Decode(key)
	if p == nil {
		return nil, errors.New("invalid pem block")
	}
	if p.Type != PrivateKeyPemType {
		return nil, fmt.Errorf("unsupported pem type: %s", p.Type)
	}

	x509Encoded, err := encrypted.Decrypt(p.Bytes, pass)
	if err != nil {
		return nil, errors.Wrap(err, "decrypt")
	}

	pk, err := x509.ParsePKCS8PrivateKey(x509Encoded)
	if err != nil {
		return nil, errors.Wrap(err, "parsing private key")
	}
	switch pk := pk.(type) {
	case *rsa.PrivateKey:
		return signature.LoadRSAPKCS1v15SignerVerifier(pk, crypto.SHA256)
	case *ecdsa.PrivateKey:
		return signature.LoadECDSASignerVerifier(pk, crypto.SHA256)
	default:
		return nil, errors.Wrap(err, "unsupported key type")
	}
}
