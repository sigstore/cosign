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
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/digitorus/timestamp"
	"github.com/sigstore/cosign/internal/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/bundle"
	"github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/cosign/pkg/oci/mutate"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	tsaclient "github.com/sigstore/timestamp-authority/pkg/generated/client"
	ts "github.com/sigstore/timestamp-authority/pkg/generated/client/timestamp"
)

func GetTimestampedSignature(sigBytes []byte, tsaClient *tsaclient.TimestampAuthority) ([]byte, error) {
	requestBytes, err := createTimestampAuthorityRequest(sigBytes, crypto.SHA256, "")
	if err != nil {
		return nil, err
	}
	fmt.Fprintln(os.Stderr, "Calling TSA authority ...")
	params := ts.NewGetTimestampResponseParams()
	params.SetTimeout(time.Second * 10)
	params.Request = io.NopCloser(bytes.NewReader(requestBytes))

	var respBytes bytes.Buffer
	_, err = tsaClient.Timestamp.GetTimestampResponse(params, &respBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to get the response: %w", err)
	}

	// validate that timestamp is parseable
	ts, err := timestamp.ParseResponse(respBytes.Bytes())
	if err != nil {
		return nil, err
	}

	fmt.Fprintln(os.Stderr, "Timestamp fetched with time:", ts.Time)

	return respBytes.Bytes(), nil
}

// signerWrapper calls a wrapped, inner signer then uploads either the Cert or Pub(licKey) of the results to Rekor, then adds the resulting `Bundle`
type signerWrapper struct {
	inner cosign.Signer

	tsaClient *tsaclient.TimestampAuthority
}

var _ cosign.Signer = (*signerWrapper)(nil)

// Sign implements `cosign.Signer`
func (rs *signerWrapper) Sign(ctx context.Context, payload io.Reader) (oci.Signature, crypto.PublicKey, error) {
	sig, pub, err := rs.inner.Sign(ctx, payload)
	if err != nil {
		return nil, nil, err
	}

	b64Sig, err := sig.Base64Signature()
	if err != nil {
		return nil, nil, err
	}
	sigBytes, err := base64.StdEncoding.DecodeString(b64Sig)
	if err != nil {
		return nil, nil, err
	}

	// Here we get the response from the timestamped authority server
	responseBytes, err := GetTimestampedSignature(sigBytes, rs.tsaClient)
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
func NewSigner(inner cosign.Signer, tsaClient *tsaclient.TimestampAuthority) cosign.Signer {
	return &signerWrapper{
		inner:     inner,
		tsaClient: tsaClient,
	}
}
