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

package payload

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"io"

	"github.com/sigstore/cosign/internal/pkg/cosign"
	"github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/cosign/pkg/oci/static"
	"github.com/sigstore/sigstore/pkg/signature"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
)

type payloadSigner struct {
	payloadSigner         signature.Signer
	payloadSignerOpts     []signature.SignOption
	publicKeyProviderOpts []signature.PublicKeyOption
}

var _ cosign.Signer = (*payloadSigner)(nil)

// Sign implements `Signer`
func (ps *payloadSigner) Sign(ctx context.Context, payload io.Reader) (oci.Signature, crypto.PublicKey, error) {
	payloadBytes, err := io.ReadAll(payload)
	if err != nil {
		return nil, nil, err
	}
	sOpts := []signature.SignOption{signatureoptions.WithContext(ctx)}
	sOpts = append(sOpts, ps.payloadSignerOpts...)
	sig, err := ps.payloadSigner.SignMessage(bytes.NewReader(payloadBytes), sOpts...)
	if err != nil {
		return nil, nil, err
	}

	pkOpts := []signature.PublicKeyOption{signatureoptions.WithContext(ctx)}
	pkOpts = append(pkOpts, ps.publicKeyProviderOpts...)
	pk, err := ps.payloadSigner.PublicKey(pkOpts...)
	if err != nil {
		return nil, nil, err
	}

	b64sig := base64.StdEncoding.EncodeToString(sig)
	ociSig, err := static.NewSignature(payloadBytes, b64sig)
	if err != nil {
		return nil, nil, err
	}

	return ociSig, pk, nil
}

// NewSigner returns a `cosign.Signer` uses the given `signature.Signer` to sign the requested payload, then returns the signature, the public key associated with it, the signed payload
func NewSigner(s signature.Signer,
	sOpts []signature.SignOption,
	pkOpts []signature.PublicKeyOption) cosign.Signer {
	return &payloadSigner{
		payloadSigner:         s,
		payloadSignerOpts:     sOpts,
		publicKeyProviderOpts: pkOpts,
	}
}
