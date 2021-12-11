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

package mutate

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"io"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/cosign/pkg/oci/static"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

type sigWrapper struct {
	wrapped oci.Signature

	annotations map[string]string
	bundle      *oci.Bundle
	cert        *x509.Certificate
	chain       []*x509.Certificate
	mediaType   types.MediaType
}

var _ v1.Layer = (*sigWrapper)(nil)
var _ oci.Signature = (*sigWrapper)(nil)

func copyAnnotations(ann map[string]string) map[string]string {
	new := make(map[string]string, len(ann))
	for k, v := range ann {
		new[k] = v
	}
	return new
}

// Annotations implements oci.Signature.
func (sw *sigWrapper) Annotations() (map[string]string, error) {
	if sw.annotations != nil {
		return copyAnnotations(sw.annotations), nil
	}
	return sw.wrapped.Annotations()
}

// Payload implements oci.Signature.
func (sw *sigWrapper) Payload() ([]byte, error) {
	return sw.wrapped.Payload()
}

// Base64Signature implements oci.Signature.
func (sw *sigWrapper) Base64Signature() (string, error) {
	return sw.wrapped.Base64Signature()
}

// Cert implements oci.Signature.
func (sw *sigWrapper) Cert() (*x509.Certificate, error) {
	if sw.cert != nil {
		return sw.cert, nil
	}
	return sw.wrapped.Cert()
}

// Chain implements oci.Signature.
func (sw *sigWrapper) Chain() ([]*x509.Certificate, error) {
	if sw.chain != nil {
		return sw.chain, nil
	}
	return sw.wrapped.Chain()
}

// Bundle implements oci.Signature.
func (sw *sigWrapper) Bundle() (*oci.Bundle, error) {
	if sw.bundle != nil {
		return sw.bundle, nil
	}
	return sw.wrapped.Bundle()
}

// MediaType implements v1.Layer
func (sw *sigWrapper) MediaType() (types.MediaType, error) {
	if sw.mediaType != "" {
		return sw.mediaType, nil
	}
	return sw.wrapped.MediaType()
}

// Digest implements v1.Layer
func (sw *sigWrapper) Digest() (v1.Hash, error) {
	return sw.wrapped.Digest()
}

// DiffID implements v1.Layer
func (sw *sigWrapper) DiffID() (v1.Hash, error) {
	return sw.wrapped.DiffID()
}

// Compressed implements v1.Layer
func (sw *sigWrapper) Compressed() (io.ReadCloser, error) {
	return sw.wrapped.Compressed()
}

// Uncompressed implements v1.Layer
func (sw *sigWrapper) Uncompressed() (io.ReadCloser, error) {
	return sw.wrapped.Uncompressed()
}

// Size implements v1.Layer
func (sw *sigWrapper) Size() (int64, error) {
	return sw.wrapped.Size()
}

// SignatureAnnotations returns a new `oci.Signature` based on the provided one
func SignatureAnnotations(sig oci.Signature, newAnnotations map[string]string) (oci.Signature, error) {
	newAnnotations = copyAnnotations(newAnnotations)
	oldAnnotations, err := sig.Annotations()
	if err != nil {
		return nil, errors.Wrap(err, "could not get annotations from signature to mutate")
	}
	newAnnotations[static.SignatureAnnotationKey] = oldAnnotations[static.SignatureAnnotationKey]
	for _, key := range []string{static.BundleAnnotationKey, static.CertificateAnnotationKey, static.ChainAnnotationKey} {
		if val, isSet := oldAnnotations[key]; isSet {
			newAnnotations[key] = val
		} else {
			delete(newAnnotations, key)
		}
	}

	return &sigWrapper{wrapped: sig, annotations: newAnnotations}, nil
}

func SignatureBundle(sig oci.Signature, newBundle *oci.Bundle) (oci.Signature, error) {
	annotations, err := sig.Annotations()
	if err != nil {
		return nil, errors.Wrap(err, "could not get annotations from signature to mutate")
	}
	delete(annotations, static.BundleAnnotationKey)
	if newBundle != nil {
		b, err := json.Marshal(newBundle)
		if err != nil {
			return nil, err
		}
		annotations[static.BundleAnnotationKey] = string(b)
	}
	return &sigWrapper{wrapped: sig, bundle: newBundle, annotations: annotations}, nil
}

func SignatureCertAndChain(sig oci.Signature, newCert, newChain []byte) (oci.Signature, error) {
	var cert *x509.Certificate
	var chain []*x509.Certificate
	var err error
	annotations, err := sig.Annotations()
	if err != nil {
		return nil, errors.Wrap(err, "could not get annotations from signature to mutate")
	}
	delete(annotations, static.CertificateAnnotationKey)
	delete(annotations, static.ChainAnnotationKey)
	if newCert != nil {
		certs, err := cryptoutils.LoadCertificatesFromPEM(bytes.NewReader(newCert))
		if err != nil {
			return nil, err
		}
		annotations[static.CertificateAnnotationKey] = string(newCert)
		cert = certs[0]
	}
	if newChain != nil {
		chain, err = cryptoutils.LoadCertificatesFromPEM(bytes.NewReader(newChain))
		if err != nil {
			return nil, err
		}
		annotations[static.ChainAnnotationKey] = string(newChain)
	}

	return &sigWrapper{wrapped: sig, cert: cert, chain: chain, annotations: annotations}, nil
}

func SignatureMediaType(sig oci.Signature, newMT types.MediaType) oci.Signature {
	return &sigWrapper{wrapped: sig, mediaType: newMT}
}
