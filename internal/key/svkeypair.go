// Copyright 2025 The Sigstore Authors.
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

package key

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/sigstore/cosign/v2/pkg/cosign"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
)

// SignerVerifierKeypair is a wrapper around a SignerVerifier that implements
// sigstore-go's Keypair interface.
type SignerVerifierKeypair struct {
	sv     signature.SignerVerifier
	hint   []byte
	keyAlg string
	sigAlg signature.AlgorithmDetails
}

// NewSignerVerifierKeypair creates a new SignerVerifierKeypair from a SignerVerifier.
func NewSignerVerifierKeypair(sv signature.SignerVerifier, defaultLoadOptions *[]signature.LoadOption) (*SignerVerifierKeypair, error) {
	pubKey, err := sv.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("getting public key: %w", err)
	}
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("marshalling public key: %w", err)
	}
	hashedBytes := sha256.Sum256(pubKeyBytes)
	hint := []byte(base64.StdEncoding.EncodeToString(hashedBytes[:]))

	var keyAlg string
	switch pubKey.(type) {
	case *ecdsa.PublicKey:
		keyAlg = "ECDSA"
	case *rsa.PublicKey:
		keyAlg = "RSA"
	case ed25519.PublicKey:
		keyAlg = "ED25519"
	default:
		return nil, errors.New("unsupported key type")
	}

	algo, err := signature.GetDefaultAlgorithmDetails(pubKey, *cosign.GetDefaultLoadOptions(defaultLoadOptions)...)
	if err != nil {
		return nil, fmt.Errorf("getting default algorithm details: %w", err)
	}

	return &SignerVerifierKeypair{
		sv:     sv,
		hint:   hint,
		keyAlg: keyAlg,
		sigAlg: algo,
	}, nil
}

// GetHashAlgorithm returns the hash algorithm to generate the digest to be signed.
func (k *SignerVerifierKeypair) GetHashAlgorithm() protocommon.HashAlgorithm {
	return k.sigAlg.GetProtoHashType()
}

func (k *SignerVerifierKeypair) GetSigningAlgorithm() protocommon.PublicKeyDetails {
	return k.sigAlg.GetSignatureAlgorithm()
}

// GetHint returns a hint for the public key.
func (k *SignerVerifierKeypair) GetHint() []byte {
	return k.hint
}

// GetKeyAlgorithm returns the key algorithm, to be used in requests to Fulcio.
func (k *SignerVerifierKeypair) GetKeyAlgorithm() string {
	return k.keyAlg
}

// GetPublicKey returns the public key.
func (k *SignerVerifierKeypair) GetPublicKey() crypto.PublicKey {
	pubKey, err := k.sv.PublicKey()
	if err != nil {
		// The interface does not allow returning an error
		return nil
	}
	return pubKey
}

// GetPublicKeyPem returns the public key in PEM format.
func (k *SignerVerifierKeypair) GetPublicKeyPem() (string, error) {
	pubKey, err := k.sv.PublicKey()
	if err != nil {
		return "", err
	}
	pemBytes, err := cryptoutils.MarshalPublicKeyToPEM(pubKey)
	if err != nil {
		return "", err
	}
	return string(pemBytes), nil
}

// SignData signs the given data with the SignerVerifier.
func (k *SignerVerifierKeypair) SignData(ctx context.Context, data []byte) ([]byte, []byte, error) {
	h := k.sigAlg.GetHashType().New()
	h.Write(data)
	digest := h.Sum(nil)
	sOpts := []signature.SignOption{signatureoptions.WithContext(ctx), signatureoptions.WithDigest(digest)}
	sig, err := k.sv.SignMessage(bytes.NewReader(data), sOpts...)
	if err != nil {
		return nil, nil, err
	}
	return sig, digest, nil
}
