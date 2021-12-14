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

package ephemeral

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"io"

	"github.com/pkg/errors"
	icosign "github.com/sigstore/cosign/internal/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/cosign/pkg/oci/static"
	"github.com/sigstore/sigstore/pkg/signature"
)

type keylessSigner struct {
	signer signature.Signer
}

var _ icosign.Signer = keylessSigner{}

// Sign implements `Signer`
func (ks keylessSigner) Sign(ctx context.Context, payload io.Reader) (oci.Signature, crypto.PublicKey, error) {
	pub, err := ks.signer.PublicKey()
	if err != nil {
		return nil, nil, errors.Wrap(err, "retrieving the static public key somehow failed")
	}

	payloadBytes, err := io.ReadAll(payload)
	if err != nil {
		return nil, nil, err
	}

	sig, err := ks.signer.SignMessage(bytes.NewReader(payloadBytes))
	if err != nil {
		return nil, nil, err
	}

	b64sig := base64.StdEncoding.EncodeToString(sig)
	ociSig, err := static.NewSignature(payloadBytes, b64sig)
	if err != nil {
		return nil, nil, err
	}

	return ociSig, pub, err
}

// NewSigner generates a new private signing key and returns a `cosign.Signer` which creates signatures with it.
func NewSigner() (icosign.Signer, error) {
	priv, err := cosign.GeneratePrivateKey()
	if err != nil {
		return nil, errors.Wrap(err, "generating cert")
	}
	s, err := signature.LoadECDSASignerVerifier(priv, crypto.SHA256)
	if err != nil {
		return nil, errors.Wrap(err, "creating a SignerVerifier from ephemeral key")
	}
	return keylessSigner{
		signer: s,
	}, nil
}
