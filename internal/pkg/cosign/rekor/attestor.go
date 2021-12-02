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

package rekor

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"io"
	"os"

	"github.com/sigstore/cosign/internal/pkg/cosign"
	cosignv1 "github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/cosign/pkg/oci/static"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func unpackAttestation(ociSig oci.Signature) (envelope []byte, cert *x509.Certificate, err error) {
	// attestations store both signatures and signed payload as an envelope in `Payload`
	envelope, err = ociSig.Payload()
	if err != nil {
		return nil, nil, err
	}

	cert, err = ociSig.Cert()
	if err != nil {
		return nil, nil, err
	}

	return envelope, cert, nil
}

// attestorWrapper calls a wrapped, inner attestor then uploads either the Cert or Pub(licKey) of the results to Rekor, then adds the resulting `Bundle`
type attestorWrapper struct {
	inner cosign.Attestor

	rClient *client.Rekor
}

var _ cosign.Attestor = (*attestorWrapper)(nil)

func (ra *attestorWrapper) Attest(ctx context.Context, payload io.Reader) (oci.Signature, crypto.PublicKey, error) {
	att, pub, err := ra.inner.Attest(ctx, payload)
	if err != nil {
		return nil, nil, err
	}

	envelope, cert, err := unpackAttestation(att)
	if err != nil {
		return nil, nil, err
	}

	rekorBytes, err := rekorBytes(cert, pub)
	if err != nil {
		return nil, nil, err
	}

	entry, err := cosignv1.TLogUploadInTotoAttestation(ctx, ra.rClient, envelope, rekorBytes)
	if err != nil {
		return nil, nil, err
	}
	// TODO: hook up to real logging
	fmt.Fprintln(os.Stderr, "tlog entry created with index:", *entry.LogIndex)

	opts := []static.Option{static.WithBundle(bundle(entry))}

	// Copy over the other attributes:
	if cert != nil {
		chain, err := att.Chain()
		if err != nil {
			return nil, nil, err
		}
		chainBytes, err := cryptoutils.MarshalCertificatesToPEM(chain)
		if err != nil {
			return nil, nil, err
		}
		opts = append(opts, static.WithCertChain(rekorBytes, chainBytes))
	}
	if annotations, err := att.Annotations(); err != nil {
		return nil, nil, err
	} else if len(annotations) > 0 {
		opts = append(opts, static.WithAnnotations(annotations))
	}
	if mt, err := att.MediaType(); err != nil {
		return nil, nil, err
	} else if mt != "" {
		opts = append(opts, static.WithLayerMediaType(mt))
	}

	newAtt, err := static.NewAttestation(envelope, opts...)
	if err != nil {
		return nil, nil, err
	}

	return newAtt, pub, nil
}

// NewInTotoAttestor returns a `cosign.Attestor` which uploads the InToto attestation to Rekor
func NewInTotoAttestor(inner cosign.Attestor, rClient *client.Rekor) cosign.Attestor {
	return &attestorWrapper{
		inner:   inner,
		rClient: rClient,
	}
}
