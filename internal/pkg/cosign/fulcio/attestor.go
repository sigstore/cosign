// Copyright 2022 The Sigstore Authors.
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
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"io"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/internal/pkg/cosign"
	"github.com/sigstore/cosign/internal/pkg/cosign/oidc"
	"github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/cosign/pkg/oci/static"
	"github.com/sigstore/cosign/pkg/types"
	"github.com/sigstore/sigstore/pkg/signature"
)

type attestor struct {
	signer      signature.Signer
	oidp        oidc.Provider
	payloadType string
}

var _ cosign.DSSEAttestor = (*attestor)(nil)

// Attest implements `cosign.DSSEAttestor`
func (pa *attestor) DSSEAttest(ctx context.Context, payload io.Reader) (oci.Signature, crypto.PublicKey, error) {
	p, err := io.ReadAll(payload)
	if err != nil {
		return nil, nil, err
	}

	pb := dsse.PAE(pa.payloadType, p)

	sig, err := pa.signer.SignMessage(bytes.NewReader(pb))
	if err != nil {
		return nil, nil, err
	}
	pk, err := pa.signer.PublicKey()
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

// NewDSSEAttestor returns a `cosign.DSSEAttestor`
func NewDSSEAttestor(payloadType string,
	s signature.Signer, oidp oidc.Provider) cosign.DSSEAttestor {
	return &attestor{
		signer:      s,
		payloadType: payloadType,
		oidp:        oidp,
	}
}

func NewKeylessDSSEAttestor(payloadType string, oidp oidc.Provider) cosign.DSSEAttestor {
	var s signature.Signer
	// create an ephemeral keypair...
	return &attestor{
		signer:      s,
		payloadType: payloadType,
		oidp:        oidp,
	}
}
