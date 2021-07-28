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

package cli

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/kubernetes"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms"
	"github.com/theupdateframework/go-tuf/encrypted"
)

func loadKey(keyPath string, pf cosign.PassFunc) (*signature.ECDSASignerVerifier, error) {
	kb, err := ioutil.ReadFile(filepath.Clean(keyPath))
	if err != nil {
		return nil, err
	}
	pass, err := pf(false)
	if err != nil {
		return nil, err
	}
	return LoadECDSAPrivateKey(kb, pass)
}

func loadPublicKey(raw []byte) (signature.Verifier, error) {
	// PEM encoded file.
	ed, err := cosign.PemToECDSAKey(raw)
	if err != nil {
		return nil, errors.Wrap(err, "pem to ecdsa")
	}
	return signature.LoadECDSAVerifier(ed, crypto.SHA256)
}

func signerFromKeyRef(ctx context.Context, keyRef string, pf cosign.PassFunc) (signature.Signer, error) {
	return signerVerifierFromKeyRef(ctx, keyRef, pf)
}

func signerVerifierFromKeyRef(ctx context.Context, keyRef string, pf cosign.PassFunc) (signature.SignerVerifier, error) {
	for prefix := range kms.ProvidersMux().Providers() {
		if strings.HasPrefix(keyRef, prefix) {
			return kms.Get(ctx, keyRef, crypto.SHA256)
		}
	}

	if strings.HasPrefix(keyRef, kubernetes.KeyReference) {
		s, err := kubernetes.GetKeyPairSecret(ctx, keyRef)
		if err != nil {
			return nil, err
		}

		if len(s.Data) > 0 {
			return LoadECDSAPrivateKey(s.Data["cosign.key"], s.Data["cosign.password"])
		}
	}

	return loadKey(keyRef, pf)
}

func publicKeyFromKeyRef(ctx context.Context, keyRef string) (signature.Verifier, error) {
	if strings.HasPrefix(keyRef, kubernetes.KeyReference) {
		s, err := kubernetes.GetKeyPairSecret(ctx, keyRef)
		if err != nil {
			return nil, err
		}

		if len(s.Data) > 0 {
			return loadPublicKey(s.Data["cosign.pub"])
		}
	}

	return LoadPublicKey(ctx, keyRef)
}

func publicKeyPem(key signature.PublicKeyProvider, pkOpts ...signature.PublicKeyOption) ([]byte, error) {
	pub, err := key.PublicKey(pkOpts...)
	if err != nil {
		return nil, err
	}
	return cryptoutils.MarshalPublicKeyToPEM(pub)
}

func LoadECDSAPrivateKey(key []byte, pass []byte) (*signature.ECDSASignerVerifier, error) {
	// Decrypt first
	p, _ := pem.Decode(key)
	if p == nil {
		return nil, errors.New("invalid pem block")
	}
	if p.Type != cosign.PrivakeKeyPemType {
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
	epk, ok := pk.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid private key")
	}
	return signature.LoadECDSASignerVerifier(epk, crypto.SHA256)
}
