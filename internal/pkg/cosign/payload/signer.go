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
	"fmt"
	"io"

	"github.com/sigstore/cosign/v2/internal/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
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
	sig, err := ps.signPayload(ctx, payloadBytes)
	if err != nil {
		return nil, nil, err
	}
	pk, err := ps.publicKey(ctx)
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

func (ps *payloadSigner) publicKey(ctx context.Context) (pk crypto.PublicKey, err error) {
	pkOpts := []signature.PublicKeyOption{signatureoptions.WithContext(ctx)}
	pkOpts = append(pkOpts, ps.publicKeyProviderOpts...)
	pk, err = ps.payloadSigner.PublicKey(pkOpts...)
	if err != nil {
		return nil, err
	}
	return pk, nil
}

func (ps *payloadSigner) signPayload(ctx context.Context, payloadBytes []byte) (sig []byte, err error) {
	sOpts := []signature.SignOption{signatureoptions.WithContext(ctx)}
	sOpts = append(sOpts, ps.payloadSignerOpts...)
	sig, err = ps.payloadSigner.SignMessage(bytes.NewReader(payloadBytes), sOpts...)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

func newSigner(s signature.Signer,
	signAndPublicKeyOptions ...interface{}) payloadSigner {
	var sOpts []signature.SignOption
	var pkOpts []signature.PublicKeyOption

	for _, opt := range signAndPublicKeyOptions {
		switch o := opt.(type) {
		case signature.SignOption:
			sOpts = append(sOpts, o)
		case signature.PublicKeyOption:
			pkOpts = append(pkOpts, o)
		default:
			panic(fmt.Sprintf("options must be of type `signature.SignOption` or `signature.PublicKeyOption`. Got a %T: %v", o, o))
		}
	}

	return payloadSigner{
		payloadSigner:         s,
		payloadSignerOpts:     sOpts,
		publicKeyProviderOpts: pkOpts,
	}
}

// NewSigner returns a `cosign.Signer` which uses the given `signature.Signer` to sign requested payloads.
// Option types other than `signature.SignOption` and `signature.PublicKeyOption` cause a runtime panic.
func NewSigner(s signature.Signer,
	signAndPublicKeyOptions ...interface{}) cosign.Signer {
	signer := newSigner(s, signAndPublicKeyOptions...)
	return &signer
}
