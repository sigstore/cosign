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
	"encoding/json"
	"io"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/internal/pkg/cosign"
	"github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/cosign/pkg/oci/static"
	"github.com/sigstore/cosign/pkg/types"
	"github.com/sigstore/sigstore/pkg/signature"
)

type payloadAttestor struct {
	payloadSigner

	payloadType string
}

var _ cosign.DSSEAttestor = (*payloadAttestor)(nil)

// Attest implements `cosign.DSSEAttestor`
func (pa *payloadAttestor) DSSEAttest(ctx context.Context, payload io.Reader) (oci.Signature, crypto.PublicKey, error) {
	p, err := io.ReadAll(payload)
	if err != nil {
		return nil, nil, err
	}
	pae := dsse.PAE(pa.payloadType, p)

	pb, sig, pk, err := pa.signPayload(ctx, bytes.NewReader(pae))
	if err != nil {
		return nil, nil, err
	}

	envelope := dsse.Envelope{
		PayloadType: pa.payloadType,
		Payload:     base64.StdEncoding.EncodeToString(pb),
		Signatures: []dsse.Signature{{
			Sig: base64.StdEncoding.EncodeToString(sig),
		}},
	}

	envelopeJSON, err := json.Marshal(envelope)
	if err != nil {
		return nil, nil, err
	}

	opts := []static.Option{static.WithLayerMediaType(types.DssePayloadType)}

	att, err := static.NewAttestation(envelopeJSON, opts...)
	if err != nil {
		return nil, nil, err
	}

	return att, pk, nil
}

// NewDSSEAttestor returns a `cosign.DSSEAttestor` which uses the given `signature.Signer` to sign and create a DSSE attestation of given payloads.
func NewDSSEAttestor(payloadType string,
	s signature.Signer,
	sOpts []signature.SignOption,
	pkOpts []signature.PublicKeyOption) cosign.DSSEAttestor {
	return &payloadAttestor{
		payloadSigner: newSigner(s, sOpts, pkOpts),
		payloadType:   payloadType,
	}
}
