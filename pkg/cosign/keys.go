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
	"crypto/ed25519"
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
	CosignPrivateKeyPemType = "ENCRYPTED COSIGN PRIVATE KEY"
	// PEM-encoded PKCS #1 RSA private key
	RSAPrivateKeyPemType = "RSA PRIVATE KEY"
	// PEM-encoded ECDSA private key
	ECPrivateKeyPemType = "EC PRIVATE KEY"
	// PEM-encoded PKCS #8 RSA, ECDSA or ED25519 private key
	PrivateKeyPemType = "PRIVATE KEY"
	BundleKey         = static.BundleAnnotationKey
)

// PassFunc is the function to be called to retrieve the signer password. If
// nil, then it assumes that no password is provided.
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

// Enforce a minimum and maximum RSA key size.
func validateRsaKey(pk *rsa.PrivateKey) error {
	// Key size is the bit length of modulus
	keySize := pk.N.BitLen()
	if keySize < 2048 {
		return fmt.Errorf("rsa key size too small, expected >= 2048")
	}
	if keySize > 4096 {
		return fmt.Errorf("rsa key size too large, expected <= 4096")
	}
	return nil
}

// Enforce that the ECDSA key curve is one of:
// * NIST P-256 (secp256r1, prime256v1)
// * NIST P-384
// * NIST P-521.
// Other EC curves, like secp256k1, are not supported by Go.
func validateEcdsaKey(pk *ecdsa.PrivateKey) error {
	switch pk.Curve {
	case elliptic.P224():
		return fmt.Errorf("unsupported ec curve, expected NIST P-256, P-384, or P-521")
	case elliptic.P256(), elliptic.P384(), elliptic.P521():
		return nil
	default:
		return fmt.Errorf("unexpected ec curve")
	}
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
		return nil, fmt.Errorf("invalid pem block")
	}

	var pk crypto.Signer

	switch p.Type {
	case RSAPrivateKeyPemType:
		rsaPk, err := x509.ParsePKCS1PrivateKey(p.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing rsa private key")
		}
		if err = validateRsaKey(rsaPk); err != nil {
			return nil, errors.Wrap(err, "error validating rsa key")
		}
		pk = rsaPk
	case ECPrivateKeyPemType:
		ecdsaPk, err := x509.ParseECPrivateKey(p.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing ecdsa private key")
		}
		if err = validateEcdsaKey(ecdsaPk); err != nil {
			return nil, errors.Wrap(err, "error validating ecdsa key")
		}
		pk = ecdsaPk
	case PrivateKeyPemType:
		pkcs8Pk, err := x509.ParsePKCS8PrivateKey(p.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing pkcs #8 private key")
		}
		switch k := pkcs8Pk.(type) {
		case *rsa.PrivateKey:
			if err = validateRsaKey(k); err != nil {
				return nil, errors.Wrap(err, "error validating rsa key")
			}
			pk = k
		case *ecdsa.PrivateKey:
			if err = validateEcdsaKey(k); err != nil {
				return nil, errors.Wrap(err, "error validating ecdsa key")
			}
			pk = k
		case ed25519.PrivateKey:
			// Nothing to validate, since ED25519 supports only one key size.
			pk = k
		default:
			return nil, fmt.Errorf("unexpected private key")
		}
	default:
		return nil, fmt.Errorf("unsupported private key")
	}
	return marshalKeyPair(Keys{pk, pk.Public()}, pf)
}

func marshalKeyPair(keypair Keys, pf PassFunc) (key *KeysBytes, err error) {
	x509Encoded, err := x509.MarshalPKCS8PrivateKey(keypair.private)
	if err != nil {
		return nil, errors.Wrap(err, "x509 encoding private key")
	}

	password := []byte{}
	if pf != nil {
		password, err = pf(true)
		if err != nil {
			return nil, err
		}
	}

	encBytes, err := encrypted.Encrypt(x509Encoded, password)
	if err != nil {
		return nil, err
	}

	// store in PEM format
	privBytes := pem.EncodeToMemory(&pem.Block{
		Bytes: encBytes,
		Type:  CosignPrivateKeyPemType,
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
	if p.Type != CosignPrivateKeyPemType {
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
	case ed25519.PrivateKey:
		return signature.LoadED25519SignerVerifier(pk)
	default:
		return nil, errors.New("unsupported key type")
	}
}
