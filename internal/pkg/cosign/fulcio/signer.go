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
	"encoding/json"
	"io"

	"github.com/pkg/errors"
	"github.com/sigstore/cosign/internal/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/tuf"
	"github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/cosign/pkg/oci/mutate"
)

// signerWrapper still needs to actually upload keys to Fulcio and receive
// the resulting `Cert` and `Chain`, which are added to the returned `oci.Signature`
type signerWrapper struct {
	inner cosign.Signer

	cert, chain []byte
}

// getTimestamp fetches the TUF timestamp metadata to be bundled
// with the OCI signature.
func getTimestamp(ctx context.Context) (*oci.Timestamp, error) {
	tuf, err := tuf.NewFromEnv(ctx)
	if err != nil {
		return nil, err
	}
	defer tuf.Close()
	tsBytes, err := tuf.GetTimestamp()
	if err != nil {
		return nil, err
	}
	var timestamp oci.Timestamp
	if err := json.Unmarshal(tsBytes, &timestamp); err != nil {
		return nil, errors.Wrap(err, "unable to unmarshal timestamp")
	}
	return &timestamp, nil
}

var _ cosign.Signer = (*signerWrapper)(nil)

// Sign implements `cosign.Signer`
func (fs *signerWrapper) Sign(ctx context.Context, payload io.Reader) (oci.Signature, crypto.PublicKey, error) {
	sig, pub, err := fs.inner.Sign(ctx, payload)
	if err != nil {
		return nil, nil, err
	}

	timestamp, err := getTimestamp(ctx)
	if err != nil {
		return nil, nil, err
	}

	// TODO(dekkagaijin): move the fulcio SignerVerifier logic here
	newSig, err := mutate.Signature(sig, mutate.WithCertChain(fs.cert, fs.chain), mutate.WithTimestamp(timestamp))
	if err != nil {
		return nil, nil, err
	}

	return newSig, pub, nil
}

// NewSigner returns a `cosign.Signer` which leverages Fulcio to create a Cert and Chain for the signature
func NewSigner(inner cosign.Signer, cert, chain []byte) cosign.Signer {
	return &signerWrapper{
		inner: inner,
		cert:  cert,
		chain: chain,
	}
}
