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
	"encoding/base64"
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

func unpackSignature(ociSig oci.Signature) (payload []byte, b64Sig string, sig []byte, cert *x509.Certificate, err error) {
	payload, err = ociSig.Payload()
	if err != nil {
		return nil, "", nil, nil, err
	}
	b64Sig, err = ociSig.Base64Signature()
	if err != nil {
		return nil, "", nil, nil, err
	}
	sig, err = base64.StdEncoding.DecodeString(b64Sig)
	if err != nil {
		return nil, "", nil, nil, err
	}

	cert, err = ociSig.Cert()
	if err != nil {
		return nil, "", nil, nil, err
	}

	return payload, b64Sig, sig, cert, nil
}

// signerWrapper calls a wrapped, inner signer then uploads either the Cert or Pub(licKey) of the results to Rekor, then adds the resulting `Bundle`
type signerWrapper struct {
	inner cosign.Signer

	rClient *client.Rekor
}

var _ cosign.Signer = (*signerWrapper)(nil)

// Sign implements `cosign.Signer`
func (rs *signerWrapper) Sign(ctx context.Context, payload io.Reader) (oci.Signature, crypto.PublicKey, error) {
	sig, pub, err := rs.inner.Sign(ctx, payload)
	if err != nil {
		return nil, nil, err
	}

	payloadBytes, b64Sig, sigBytes, cert, err := unpackSignature(sig)
	if err != nil {
		return nil, nil, err
	}

	rekorBytes, err := rekorBytes(cert, pub)
	if err != nil {
		return nil, nil, err
	}

	entry, err := cosignv1.TLogUpload(ctx, rs.rClient, sigBytes, payloadBytes, rekorBytes)
	if err != nil {
		return nil, nil, err
	}
	// TODO: hook up to real logging
	fmt.Fprintln(os.Stderr, "tlog entry created with index:", *entry.LogIndex)

	opts := []static.Option{static.WithBundle(bundle(entry))}

	// Copy over the other attributes:
	if cert != nil {
		chain, err := sig.Chain()
		if err != nil {
			return nil, nil, err
		}
		chainBytes, err := cryptoutils.MarshalCertificatesToPEM(chain)
		if err != nil {
			return nil, nil, err
		}
		opts = append(opts, static.WithCertChain(rekorBytes, chainBytes))
	}
	if annotations, err := sig.Annotations(); err != nil {
		return nil, nil, err
	} else if len(annotations) > 0 {
		opts = append(opts, static.WithAnnotations(annotations))
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

// NewSigner returns a `cosign.Signer` which uploads the signature to Rekor
func NewSigner(inner cosign.Signer, rClient *client.Rekor) cosign.Signer {
	return &signerWrapper{
		inner:   inner,
		rClient: rClient,
	}
}
