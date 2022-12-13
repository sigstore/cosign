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
	"fmt"
	"io"

	icosign "github.com/sigstore/cosign/v2/internal/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	"github.com/sigstore/sigstore/pkg/signature"
)

type ephemeralSigner struct {
	signer signature.Signer
}

var _ icosign.Signer = ephemeralSigner{}

// Sign implements `Signer`
func (ks ephemeralSigner) Sign(ctx context.Context, payload io.Reader) (oci.Signature, crypto.PublicKey, error) {
	pub, err := ks.signer.PublicKey()
	if err != nil {
		return nil, nil, fmt.Errorf("retrieving the static public key somehow failed: %w", err)
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
		return nil, fmt.Errorf("generating cert: %w", err)
	}
	s, err := signature.LoadECDSASignerVerifier(priv, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("creating a SignerVerifier from ephemeral key: %w", err)
	}
	return ephemeralSigner{
		signer: s,
	}, nil
}
