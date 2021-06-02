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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	_ "crypto/sha256" // for `crypto.SHA256`
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/theupdateframework/go-tuf/encrypted"

	"github.com/sigstore/sigstore/pkg/kms"
	"github.com/sigstore/sigstore/pkg/signature"
)

const (
	PemType   = "ENCRYPTED COSIGN PRIVATE KEY"
	sigkey    = "dev.cosignproject.cosign/signature"
	certkey   = "dev.sigstore.cosign/certificate"
	chainkey  = "dev.sigstore.cosign/chain"
	BundleKey = "dev.sigstore.cosign/bundle"
)

type PassFunc func(bool) ([]byte, error)

type Keys struct {
	PrivateBytes []byte
	PublicBytes  []byte
	password     []byte
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
		Type:  PemType,
	})

	// Now do the public key
	pubBytes, err := KeyToPem(&priv.PublicKey)
	if err != nil {
		return nil, err
	}

	return &Keys{
		PrivateBytes: privBytes,
		PublicBytes:  pubBytes,
		password:     password,
	}, nil
}

func (k *Keys) Password() []byte {
	return k.password
}

func PublicKeyPem(ctx context.Context, key signature.PublicKeyProvider) ([]byte, error) {
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

func LoadECDSAPrivateKey(key []byte, pass []byte) (signature.ECDSASignerVerifier, error) {
	// Decrypt first
	p, _ := pem.Decode(key)
	if p == nil {
		return signature.ECDSASignerVerifier{}, errors.New("invalid pem block")
	}
	if p.Type != PemType {
		return signature.ECDSASignerVerifier{}, fmt.Errorf("unsupported pem type: %s", p.Type)
	}

	x509Encoded, err := encrypted.Decrypt(p.Bytes, pass)
	if err != nil {
		return signature.ECDSASignerVerifier{}, errors.Wrap(err, "decrypt")
	}

	pk, err := x509.ParsePKCS8PrivateKey(x509Encoded)
	if err != nil {
		return signature.ECDSASignerVerifier{}, errors.Wrap(err, "parsing private key")
	}
	epk, ok := pk.(*ecdsa.PrivateKey)
	if !ok {
		return signature.ECDSASignerVerifier{}, fmt.Errorf("invalid private key")
	}
	return signature.NewECDSASignerVerifier(epk, crypto.SHA256), nil
}

const pubKeyPemType = "PUBLIC KEY"

type PublicKey interface {
	signature.Verifier
	signature.PublicKeyProvider
}

func LoadPublicKey(ctx context.Context, keyRef string) (pub PublicKey, err error) {
	// The key could be plaintext, in a file, at a URL, or in KMS.
	if kmsKey, err := kms.Get(ctx, keyRef); err == nil {
		// KMS specified
		return kmsKey, nil
	}

	var raw []byte

	if strings.HasPrefix(keyRef, "http://") || strings.HasPrefix(keyRef, "https://") {
		// key-url specified
		// #nosec G107
		resp, err := http.Get(keyRef)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		raw, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
	} else if raw, err = ioutil.ReadFile(filepath.Clean(keyRef)); err != nil {
		return nil, err
	}

	// PEM encoded file.
	ed, err := PemToECDSAKey(raw)
	if err != nil {
		return nil, errors.Wrap(err, "pem to ecdsa")
	}
	return signature.ECDSAVerifier{Key: ed, HashAlg: crypto.SHA256}, nil
}

func PemToECDSAKey(raw []byte) (*ecdsa.PublicKey, error) {
	p, _ := pem.Decode(raw)
	if p == nil {
		return nil, errors.New("pem.Decode failed")
	}
	if p.Type != pubKeyPemType {
		return nil, fmt.Errorf("not public: %q", p.Type)
	}

	decoded, err := x509.ParsePKIXPublicKey(p.Bytes)
	if err != nil {
		return nil, err
	}
	ed, ok := decoded.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid public key: was %T, require *ecdsa.PublicKey", raw)
	}
	return ed, nil
}
