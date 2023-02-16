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

package tsa

import (
	"bytes"
	"context"
	"crypto"
	"io"
	"strconv"
	"strings"

	"github.com/digitorus/timestamp"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/v2/internal/pkg/cosign"
	"github.com/sigstore/cosign/v2/internal/pkg/cosign/tsa/client"
	"github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/mutate"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// GetTimestampedSignature queries a timestamp authority to fetch an RFC3161 timestamp. sigBytes is an
// opaque blob, but is typically a signature over an artifact.
func GetTimestampedSignature(sigBytes []byte, tsaClient client.TimestampAuthorityClient) ([]byte, error) {
	requestBytes, err := createTimestampAuthorityRequest(sigBytes, crypto.SHA256, "")
	if err != nil {
		return nil, errors.Wrap(err, "error creating timestamp request")
	}

	return tsaClient.GetTimestampResponse(requestBytes)
}

// signerWrapper calls a wrapped, inner signer then uploads either the Cert or Pub(licKey) of the results to Rekor, then adds the resulting `Bundle`
type signerWrapper struct {
	inner cosign.Signer

	tsaClient client.TimestampAuthorityClient
}

var _ cosign.Signer = (*signerWrapper)(nil)

// Sign implements `cosign.Signer`
func (rs *signerWrapper) Sign(ctx context.Context, payload io.Reader) (oci.Signature, crypto.PublicKey, error) {
	sig, pub, err := rs.inner.Sign(ctx, payload)
	if err != nil {
		return nil, nil, err
	}

	// create timestamp over raw bytes of signature
	rawSig, err := sig.Signature()
	if err != nil {
		return nil, nil, err
	}

	// fetch rfc3161 timestamp from timestamp authority
	responseBytes, err := GetTimestampedSignature(rawSig, rs.tsaClient)
	if err != nil {
		return nil, nil, err
	}
	bundle := bundle.TimestampToRFC3161Timestamp(responseBytes)

	newSig, err := mutate.Signature(sig, mutate.WithRFC3161Timestamp(bundle))
	if err != nil {
		return nil, nil, err
	}

	return newSig, pub, nil
}

func createTimestampAuthorityRequest(artifactBytes []byte, hash crypto.Hash, policyStr string) ([]byte, error) {
	reqOpts := &timestamp.RequestOptions{
		Hash:         hash,
		Certificates: true, // if the timestamp response should contain the leaf certificate
	}
	// specify a pseudo-random nonce in the request
	nonce, err := cryptoutils.GenerateSerialNumber()
	if err != nil {
		return nil, err
	}
	reqOpts.Nonce = nonce

	if policyStr != "" {
		var oidInts []int
		for _, v := range strings.Split(policyStr, ".") {
			i, _ := strconv.Atoi(v)
			oidInts = append(oidInts, i)
		}
		reqOpts.TSAPolicyOID = oidInts
	}

	return timestamp.CreateRequest(bytes.NewReader(artifactBytes), reqOpts)
}

// NewSigner returns a `cosign.Signer` which uploads the signature to a TSA
func NewSigner(inner cosign.Signer, tsaClient client.TimestampAuthorityClient) cosign.Signer {
	return &signerWrapper{
		inner:     inner,
		tsaClient: tsaClient,
	}
}
