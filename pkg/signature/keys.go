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

package signature

import (
	"context"
	"crypto"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

	"github.com/sigstore/cosign/pkg/blob"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/kubernetes"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms"
)

func LoadPublicKey(ctx context.Context, keyRef string) (verifier signature.Verifier, err error) {
	// The key could be plaintext, in a file, at a URL, or in KMS.
	if kmsKey, err := kms.Get(ctx, keyRef, crypto.SHA256); err == nil {
		// KMS specified
		return kmsKey, nil
	}

	raw, err := blob.LoadFileOrURL(keyRef)

	if err != nil {
		return nil, err
	}

	// PEM encoded file.
	ed, err := cosign.PemToECDSAKey(raw)
	if err != nil {
		return nil, errors.Wrap(err, "pem to ecdsa")
	}
	return signature.LoadECDSAVerifier(ed, crypto.SHA256)
}

func loadKey(keyPath string, pf cosign.PassFunc) (*signature.ECDSASignerVerifier, error) {
	kb, err := ioutil.ReadFile(filepath.Clean(keyPath))
	if err != nil {
		return nil, err
	}
	pass, err := pf(false)
	if err != nil {
		return nil, err
	}
	return cosign.LoadECDSAPrivateKey(kb, pass)
}

func loadPublicKey(raw []byte) (signature.Verifier, error) {
	// PEM encoded file.
	ed, err := cosign.PemToECDSAKey(raw)
	if err != nil {
		return nil, errors.Wrap(err, "pem to ecdsa")
	}
	return signature.LoadECDSAVerifier(ed, crypto.SHA256)
}

func SignerFromKeyRef(ctx context.Context, keyRef string, pf cosign.PassFunc) (signature.Signer, error) {
	return SignerVerifierFromKeyRef(ctx, keyRef, pf)
}

func SignerVerifierFromKeyRef(ctx context.Context, keyRef string, pf cosign.PassFunc) (signature.SignerVerifier, error) {
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
			return cosign.LoadECDSAPrivateKey(s.Data["cosign.key"], s.Data["cosign.password"])
		}
	}

	return loadKey(keyRef, pf)
}

func PublicKeyFromKeyRef(ctx context.Context, keyRef string) (signature.Verifier, error) {
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

func PublicKeyPem(key signature.PublicKeyProvider, pkOpts ...signature.PublicKeyOption) ([]byte, error) {
	pub, err := key.PublicKey(pkOpts...)
	if err != nil {
		return nil, err
	}
	return cryptoutils.MarshalPublicKeyToPEM(pub)
}
