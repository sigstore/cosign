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
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256" // for `crypto.SHA256`
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/secure-systems-lab/go-securesystemslib/encrypted"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

const (
	CosignPrivateKeyPemType   = "ENCRYPTED COSIGN PRIVATE KEY"
	SigstorePrivateKeyPemType = "ENCRYPTED SIGSTORE PRIVATE KEY"
	// PEM-encoded PKCS #1 RSA private key
	RSAPrivateKeyPemType = "RSA PRIVATE KEY"
	// PEM-encoded ECDSA private key
	ECPrivateKeyPemType = "EC PRIVATE KEY"
	// PEM-encoded PKCS #8 RSA, ECDSA or ED25519 private key
	PrivateKeyPemType   = "PRIVATE KEY"
	BundleKey           = static.BundleAnnotationKey
	RFC3161TimestampKey = static.RFC3161TimestampAnnotationKey
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

func (k *KeysBytes) Password() []byte {
	return k.password
}

// GeneratePrivateKey generates an ECDSA private key with the P-256 curve.
func GeneratePrivateKey() (*ecdsa.PrivateKey, error) {
	priv, err := GeneratePrivateKeyWithAlgorithm(nil)
	if err != nil {
		return nil, err
	}
	return priv.(*ecdsa.PrivateKey), nil
}

// GeneratePrivateKeyWithAlgorithm generates a private key for the given algorithm
func GeneratePrivateKeyWithAlgorithm(algo *signature.AlgorithmDetails) (crypto.PrivateKey, error) {
	var currentAlgo signature.AlgorithmDetails
	if algo == nil {
		var err error
		currentAlgo, err = signature.GetAlgorithmDetails(v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256)
		if err != nil {
			return nil, fmt.Errorf("error getting algorithm details for default algorithm: %w", err)
		}
	} else {
		currentAlgo = *algo
	}

	switch currentAlgo.GetKeyType() {
	case signature.ECDSA:
		curve, err := currentAlgo.GetECDSACurve()
		if err != nil {
			return nil, fmt.Errorf("error getting ECDSA curve: %w", err)
		}
		return ecdsa.GenerateKey(*curve, rand.Reader)
	case signature.RSA:
		rsaKeySize, err := currentAlgo.GetRSAKeySize()
		if err != nil {
			return nil, fmt.Errorf("error getting RSA key size: %w", err)
		}
		return rsa.GenerateKey(rand.Reader, int(rsaKeySize))
	case signature.ED25519:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("error generating ED25519 key: %w", err)
		}
		return priv, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %v", currentAlgo.GetKeyType())
	}
}

// ImportKeyPair imports a key pair from a file containing a PEM-encoded
// private key encoded with a password provided by the 'pf' function.
// The private key can be in one of the following formats:
// - RSA private key (PKCS #1)
// - ECDSA private key
// - PKCS #8 private key (RSA, ECDSA or ED25519).
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
			return nil, fmt.Errorf("error parsing rsa private key: %w", err)
		}
		if err = cryptoutils.ValidatePubKey(rsaPk.Public()); err != nil {
			return nil, fmt.Errorf("error validating rsa key: %w", err)
		}
		pk = rsaPk
	case ECPrivateKeyPemType:
		ecdsaPk, err := x509.ParseECPrivateKey(p.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing ecdsa private key")
		}
		if err = cryptoutils.ValidatePubKey(ecdsaPk.Public()); err != nil {
			return nil, fmt.Errorf("error validating ecdsa key: %w", err)
		}
		pk = ecdsaPk
	case PrivateKeyPemType:
		pkcs8Pk, err := x509.ParsePKCS8PrivateKey(p.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing pkcs #8 private key")
		}
		switch k := pkcs8Pk.(type) {
		case *rsa.PrivateKey:
			if err = cryptoutils.ValidatePubKey(k.Public()); err != nil {
				return nil, fmt.Errorf("error validating rsa key: %w", err)
			}
			pk = k
		case *ecdsa.PrivateKey:
			if err = cryptoutils.ValidatePubKey(k.Public()); err != nil {
				return nil, fmt.Errorf("error validating ecdsa key: %w", err)
			}
			pk = k
		case ed25519.PrivateKey:
			if err = cryptoutils.ValidatePubKey(k.Public()); err != nil {
				return nil, fmt.Errorf("error validating ed25519 key: %w", err)
			}
			pk = k
		default:
			return nil, fmt.Errorf("unexpected private key")
		}
	default:
		return nil, fmt.Errorf("unsupported private key")
	}
	return marshalKeyPair(p.Type, Keys{pk, pk.Public()}, pf)
}

func marshalKeyPair(ptype string, keypair Keys, pf PassFunc) (key *KeysBytes, err error) {
	x509Encoded, err := x509.MarshalPKCS8PrivateKey(keypair.private)
	if err != nil {
		return nil, fmt.Errorf("x509 encoding private key: %w", err)
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

	// default to SIGSTORE, but keep support of COSIGN
	if ptype != CosignPrivateKeyPemType {
		ptype = SigstorePrivateKeyPemType
	}

	// store in PEM format
	privBytes := pem.EncodeToMemory(&pem.Block{
		Bytes: encBytes,
		Type:  ptype,
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

	// Emit SIGSTORE keys by default
	return marshalKeyPair(SigstorePrivateKeyPemType, Keys{priv, priv.Public()}, pf)
}

func GenerateKeyPairWithAlgorithm(algo *signature.AlgorithmDetails, pf PassFunc) (*KeysBytes, error) {
	priv, err := GeneratePrivateKeyWithAlgorithm(algo)
	if err != nil {
		return nil, err
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key is not a signer verifier")
	}
	// Emit SIGSTORE keys by default
	return marshalKeyPair(SigstorePrivateKeyPemType, Keys{signer, signer.Public()}, pf)
}

// PemToECDSAKey marshals and returns the PEM-encoded ECDSA public key.
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

// LoadPrivateKey loads a cosign PEM private key encrypted with the given passphrase,
// and returns a SignerVerifier instance. The private key must be in the PKCS #8 format.
func LoadPrivateKey(key []byte, pass []byte, defaultLoadOptions *[]signature.LoadOption) (signature.SignerVerifier, error) {
	// Decrypt first
	p, _ := pem.Decode(key)
	if p == nil {
		return nil, errors.New("invalid pem block")
	}
	if p.Type != CosignPrivateKeyPemType && p.Type != SigstorePrivateKeyPemType {
		return nil, fmt.Errorf("unsupported pem type: %s", p.Type)
	}

	x509Encoded, err := encrypted.Decrypt(p.Bytes, pass)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	pk, err := x509.ParsePKCS8PrivateKey(x509Encoded)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}
	defaultLoadOptions = GetDefaultLoadOptions(defaultLoadOptions)
	return signature.LoadDefaultSignerVerifier(pk, *defaultLoadOptions...)
}

func GetDefaultLoadOptions(defaultLoadOptions *[]signature.LoadOption) *[]signature.LoadOption {
	if defaultLoadOptions == nil {
		// Cosign uses ED25519ph by default for ED25519 keys, because that's the
		// only available option for hashedrekord entries. This behaviour is
		// configurable because we want to maintain compatibility with older
		// cosign versions that used PureEd25519 for ED25519 keys (but which did
		// not support TLog uploads).
		return &[]signature.LoadOption{options.WithED25519ph()}
	}
	return defaultLoadOptions
}
