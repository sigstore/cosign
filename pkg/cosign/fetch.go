//
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
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v2/pkg/oci"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"golang.org/x/sync/errgroup"
)

const maxAllowedSigsOrAtts = 100

type SignedPayload struct {
	Base64Signature  string
	Payload          []byte
	Cert             *x509.Certificate
	Chain            []*x509.Certificate
	Bundle           *bundle.RekorBundle
	RFC3161Timestamp *bundle.RFC3161Timestamp
}

type LocalSignedPayload struct {
	Base64Signature string              `json:"base64Signature"`
	Cert            string              `json:"cert,omitempty"`
	Bundle          *bundle.RekorBundle `json:"rekorBundle,omitempty"`
}

type Signatures struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

type AttestationPayload struct {
	PayloadType string       `json:"payloadType"`
	PayLoad     string       `json:"payload"`
	Signatures  []Signatures `json:"signatures"`
}

const (
	Signature   = "signature"
	SBOM        = "sbom"
	Attestation = "attestation"
	Digest      = "digest"
)

func FetchSignaturesForReference(_ context.Context, ref name.Reference, opts ...ociremote.Option) ([]SignedPayload, error) {
	simg, err := ociremote.SignedEntity(ref, opts...)
	if err != nil {
		return nil, err
	}

	sigs, err := simg.Signatures()
	if err != nil {
		return nil, fmt.Errorf("remote image: %w", err)
	}
	l, err := sigs.Get()
	if err != nil {
		return nil, fmt.Errorf("fetching signatures: %w", err)
	}
	if len(l) == 0 {
		return nil, fmt.Errorf("no signatures associated with %s", ref)
	}
	if len(l) > maxAllowedSigsOrAtts {
		return nil, fmt.Errorf("maximum number of signatures on an image is %d, found %d", maxAllowedSigsOrAtts, len(l))
	}

	signatures := make([]SignedPayload, len(l))
	var g errgroup.Group
	g.SetLimit(runtime.NumCPU())
	for i, sig := range l {
		i, sig := i, sig
		g.Go(func() error {
			var err error
			signatures[i].Payload, err = sig.Payload()
			if err != nil {
				return err
			}
			signatures[i].Base64Signature, err = sig.Base64Signature()
			if err != nil {
				return err
			}
			signatures[i].Cert, err = sig.Cert()
			if err != nil {
				return err
			}
			signatures[i].Chain, err = sig.Chain()
			if err != nil {
				return err
			}

			signatures[i].RFC3161Timestamp, err = sig.RFC3161Timestamp()
			if err != nil {
				return err
			}

			signatures[i].Bundle, err = sig.Bundle()
			return err
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	return signatures, nil
}

func FetchAttestationsForReference(_ context.Context, ref name.Reference, predicateType string, opts ...ociremote.Option) ([]AttestationPayload, error) {
	se, err := ociremote.SignedEntity(ref, opts...)
	if err != nil {
		return nil, err
	}
	return FetchAttestations(se, predicateType)
}

func FetchAttestations(se oci.SignedEntity, predicateType string) ([]AttestationPayload, error) {
	atts, err := se.Attestations()
	if err != nil {
		return nil, fmt.Errorf("remote image: %w", err)
	}
	l, err := atts.Get()
	if err != nil {
		return nil, fmt.Errorf("fetching attestations: %w", err)
	}
	if len(l) == 0 {
		return nil, errors.New("found no attestations")
	}
	if len(l) > maxAllowedSigsOrAtts {
		errMsg := fmt.Sprintf("maximum number of attestations on an image is %d, found %d", maxAllowedSigsOrAtts, len(l))
		return nil, errors.New(errMsg)
	}

	attestations := make([]AttestationPayload, 0, len(l))
	var attMu sync.Mutex

	var g errgroup.Group
	g.SetLimit(runtime.NumCPU())

	for _, att := range l {
		att := att
		g.Go(func() error {
			rawPayload, err := att.Payload()
			if err != nil {
				return fmt.Errorf("fetching payload: %w", err)
			}
			var payload AttestationPayload
			if err := json.Unmarshal(rawPayload, &payload); err != nil {
				return fmt.Errorf("unmarshaling payload: %w", err)
			}

			if predicateType != "" {
				var decodedPayload []byte
				decodedPayload, err = base64.StdEncoding.DecodeString(payload.PayLoad)
				if err != nil {
					return fmt.Errorf("decoding payload: %w", err)
				}
				var statement in_toto.Statement
				if err := json.Unmarshal(decodedPayload, &statement); err != nil {
					return fmt.Errorf("unmarshaling statement: %w", err)
				}
				if statement.PredicateType != predicateType {
					return nil
				}
			}

			attMu.Lock()
			defer attMu.Unlock()
			attestations = append(attestations, payload)
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	if len(attestations) == 0 && predicateType != "" {
		return nil, fmt.Errorf("no attestations with predicate type '%s' found", predicateType)
	}

	return attestations, nil
}

// FetchLocalSignedPayloadFromPath fetches a local signed payload from a path to a file
func FetchLocalSignedPayloadFromPath(path string) (*LocalSignedPayload, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var b *LocalSignedPayload
	if err := json.Unmarshal(contents, &b); err != nil {
		return nil, err
	}
	return b, nil
}
