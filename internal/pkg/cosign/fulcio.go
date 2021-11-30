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

package cosign

import (
	"context"
	"crypto"
	"io"

	"github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/cosign/pkg/oci/static"
)

// FulcioSignerWrapper still needs to actually upload keys to Fulcio and receive
// the resulting `Cert` and `Chain`, which are added to the returned `oci.Signature`
type FulcioSignerWrapper struct {
	Inner Signer

	Cert, Chain []byte
}

var _ Signer = (*FulcioSignerWrapper)(nil)

// Sign implements `Signer`
func (fs *FulcioSignerWrapper) Sign(ctx context.Context, payload io.Reader) (oci.Signature, crypto.PublicKey, error) {
	sig, pub, err := fs.Inner.Sign(ctx, payload)
	if err != nil {
		return nil, nil, err
	}

	payloadBytes, err := sig.Payload()
	if err != nil {
		return nil, nil, err
	}
	b64Sig, err := sig.Base64Signature()
	if err != nil {
		return nil, nil, err
	}

	// TODO(dekkagaijin): move the fulcio SignerVerififer logic here

	opts := []static.Option{static.WithCertChain(fs.Cert, fs.Chain)}

	// Copy over the other attributes:
	if annotations, err := sig.Annotations(); err != nil {
		return nil, nil, err
	} else if len(annotations) > 0 {
		opts = append(opts, static.WithAnnotations(annotations))
	}
	if bundle, err := sig.Bundle(); err != nil {
		return nil, nil, err
	} else if bundle != nil {
		opts = append(opts, static.WithBundle(bundle))
	}
	if mt, err := sig.MediaType(); err != nil {
		return nil, nil, err
	} else if mt != "" {
		opts = append(opts, static.WithLayerMediaType(mt))
	}

	newSig, err := static.NewSignature(payloadBytes, b64Sig, opts...)
	if err != nil {
		return nil, nil, err
	}

	return newSig, pub, nil
}
