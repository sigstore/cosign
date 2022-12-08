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

package mock

import (
	"bytes"
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"time"

	"github.com/go-openapi/runtime"
	"github.com/pkg/errors"

	"github.com/digitorus/timestamp"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/timestamp-authority/pkg/generated/client"
	ts "github.com/sigstore/timestamp-authority/pkg/generated/client/timestamp"
	"github.com/sigstore/timestamp-authority/pkg/signer"
)

// TSAClient creates RFC3161 timestamps and implements client.TimestampAuthority.
// Messages to sign can either be provided in the initializer or through the request.
// Time can be provided in the initializer, or defaults to time.Now().
// All other timestamp parameters are hardcoded.
type TSAClient struct {
	Signer       crypto.Signer
	CertChain    []*x509.Certificate
	CertChainPEM string
	Time         time.Time
	Message      []byte
}

// TSAClientOptions provide customization for the mock TSA client.
type TSAClientOptions struct {
	// Time is an optional timestamp. Default is time.Now().
	Time time.Time
	// Message is the pre-hashed message to sign over, typically a raw signature.
	Message []byte
	// Signer is an optional signer created out of band. Client creates one if not set.
	Signer crypto.Signer
}

func NewTSAClient(o TSAClientOptions) (*client.TimestampAuthority, error) {
	sv := o.Signer
	if sv == nil {
		var err error
		sv, _, err = signature.NewECDSASignerVerifier(elliptic.P256(), rand.Reader, crypto.SHA256)
		if err != nil {
			return nil, err
		}
	}
	certChain, err := signer.NewTimestampingCertWithChain(context.Background(), sv)
	if err != nil {
		return nil, errors.Wrap(err, "generating timestamping cert chain")
	}
	certChainPEM, err := cryptoutils.MarshalCertificatesToPEM(certChain)
	if err != nil {
		return nil, fmt.Errorf("marshal certificates to PEM: %w", err)
	}

	return &client.TimestampAuthority{
		Timestamp: &TSAClient{
			Signer:       sv,
			CertChain:    certChain,
			CertChainPEM: string(certChainPEM),
			Time:         o.Time,
			Message:      o.Message,
		},
	}, nil
}

func (c *TSAClient) GetTimestampCertChain(_ *ts.GetTimestampCertChainParams, _ ...ts.ClientOption) (*ts.GetTimestampCertChainOK, error) {
	return &ts.GetTimestampCertChainOK{Payload: c.CertChainPEM}, nil
}

func (c *TSAClient) GetTimestampResponse(params *ts.GetTimestampResponseParams, w io.Writer, _ ...ts.ClientOption) (*ts.GetTimestampResponseCreated, error) {
	var hashAlg crypto.Hash
	var hashedMessage []byte

	if params.Request != nil {
		requestBytes, err := io.ReadAll(params.Request)
		if err != nil {
			return nil, err
		}

		req, err := timestamp.ParseRequest(requestBytes)
		if err != nil {
			return nil, err
		}
		hashAlg = req.HashAlgorithm
		hashedMessage = req.HashedMessage
	} else {
		hashAlg = crypto.SHA256
		h := hashAlg.New()
		h.Write(c.Message)
		hashedMessage = h.Sum(nil)
	}

	nonce, err := cryptoutils.GenerateSerialNumber()
	if err != nil {
		return nil, err
	}
	duration, _ := time.ParseDuration("1s")

	tsStruct := timestamp.Timestamp{
		HashAlgorithm:     hashAlg,
		HashedMessage:     hashedMessage,
		Nonce:             nonce,
		Policy:            asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 2},
		Ordering:          false,
		Accuracy:          duration,
		Qualified:         false,
		AddTSACertificate: true,
	}

	if c.Time.IsZero() {
		tsStruct.Time = time.Now()
	} else {
		tsStruct.Time = c.Time
	}

	resp, err := tsStruct.CreateResponse(c.CertChain[0], c.Signer)
	if err != nil {
		return nil, err
	}

	// write response to provided buffer and payload
	if w != nil {
		_, err := w.Write(resp)
		if err != nil {
			return nil, err
		}
	}
	return &ts.GetTimestampResponseCreated{Payload: bytes.NewBuffer(resp)}, nil
}

func (c *TSAClient) SetTransport(transport runtime.ClientTransport) {
	// nothing to do
}
