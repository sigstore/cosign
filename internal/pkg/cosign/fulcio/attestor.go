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
	"github.com/sigstore/cosign/pkg/oci/mutate"
)

// fulcioAttestor still needs to actually upload keys to Fulcio and receive
// the resulting `Cert` and `Chain`, which are added to the returned `oci.Signature`
type fulcioAttestor struct {
	inner cosign.DSSEAttestor

	cert, chain []byte
}

var _ cosign.DSSEAttestor = (*fulcioAttestor)(nil)

// Attest implements `cosign.DSSEAttestor`
func (fa *fulcioAttestor) DSSEAttest(ctx context.Context, payload io.Reader) (oci.Signature, crypto.PublicKey, error) {
	att, pub, err := fa.inner.DSSEAttest(ctx, payload)
	if err != nil {
		return nil, nil, err
	}

	newAtt, err := mutate.Signature(att, mutate.WithCertChain(fa.cert, fa.chain))
	if err != nil {
		return nil, nil, err
	}

	return newAtt, pub, nil
}

// WrapAttestor returns a `cosign.DSSEAttestor` which leverages Fulcio to create
// a Cert and Chain for the attestation's signature created by the inner `Attestor`
func WrapAttestor(inner cosign.DSSEAttestor, cert, chain []byte) cosign.DSSEAttestor {
	return &fulcioAttestor{
		inner: inner,
		cert:  cert,
		chain: chain,
	}
}
