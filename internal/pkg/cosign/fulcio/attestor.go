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

package fulcio

import (
	"context"
	"crypto"
	"io"

	"github.com/sigstore/cosign/internal/pkg/cosign"
	"github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/cosign/pkg/oci/static"
)

// fulcioAttestor still needs to actually upload keys to Fulcio and receive
// the resulting `Cert` and `Chain`, which are added to the returned `oci.Signature`
type fulcioAttestor struct {
	inner cosign.Attestor

	cert, chain []byte
}

var _ cosign.Attestor = (*fulcioAttestor)(nil)

// Attest implements `cosign.Attestor`
func (fa *fulcioAttestor) Attest(ctx context.Context, payload io.Reader) (oci.Signature, crypto.PublicKey, error) {
	att, pub, err := fa.inner.Attest(ctx, payload)
	if err != nil {
		return nil, nil, err
	}

	payloadBytes, err := att.Payload()
	if err != nil {
		return nil, nil, err
	}

	// TODO(dekkagaijin): move the fulcio SignerVerififer logic here
	opts := []static.Option{static.WithCertChain(fa.cert, fa.chain)}

	// Copy over the other attributes:
	if annotations, err := att.Annotations(); err != nil {
		return nil, nil, err
	} else if len(annotations) > 0 {
		opts = append(opts, static.WithAnnotations(annotations))
	}
	if bundle, err := att.Bundle(); err != nil {
		return nil, nil, err
	} else if bundle != nil {
		opts = append(opts, static.WithBundle(bundle))
	}
	if mt, err := att.MediaType(); err != nil {
		return nil, nil, err
	} else if mt != "" {
		opts = append(opts, static.WithLayerMediaType(mt))
	}

	newAtt, err := static.NewAttestation(payloadBytes, opts...)
	if err != nil {
		return nil, nil, err
	}

	return newAtt, pub, nil
}

// NewInTotoAttestor returns a `cosign.Attestor` which leverages Fulcio to create
// a Cert and Chain for the attestation's signature created by the inner `Attestor``
func NewInTotoAttestor(inner cosign.Attestor, cert, chain []byte) cosign.Attestor {
	return &fulcioAttestor{
		inner: inner,
		cert:  cert,
		chain: chain,
	}
}
