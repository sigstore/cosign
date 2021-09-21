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

package remote

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/go-openapi/swag"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/pkg/errors"
	"knative.dev/pkg/kmeta"

	"github.com/sigstore/cosign/internal/oci"
	"github.com/sigstore/cosign/internal/oci/empty"
	ociremote "github.com/sigstore/cosign/internal/oci/remote"
	ctypes "github.com/sigstore/cosign/pkg/types"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

const (
	sigkey    = "dev.cosignproject.cosign/signature"
	certkey   = "dev.sigstore.cosign/certificate"
	chainkey  = "dev.sigstore.cosign/chain"
	BundleKey = "dev.sigstore.cosign/bundle"
)

func Descriptors(ref name.Reference, remoteOpts ...remote.Option) ([]v1.Descriptor, error) {
	img, err := remote.Image(ref, remoteOpts...)
	if err != nil {
		return nil, err
	}
	m, err := img.Manifest()
	if err != nil {
		return nil, err
	}

	return m.Layers, nil
}

// SignatureImage returns the existing destination image, or a new, empty one.
func SignatureImage(ref name.Reference, opts ...remote.Option) (oci.Signatures, error) {
	base, err := ociremote.Signatures(ref, ociremote.WithRemoteOptions(opts...))
	if err == nil {
		return base, nil
	}
	var te *transport.Error
	if errors.As(err, &te) {
		if te.StatusCode != http.StatusNotFound {
			return nil, te
		}
		return empty.Signatures(), nil
	}
	return nil, err
}

func findDuplicate(sigImage oci.Signatures, newSig oci.Signature, dupeDetector signature.Verifier) ([]byte, error) {
	newDigest, err := newSig.Digest()
	if err != nil {
		return nil, err
	}
	newMediaType, err := newSig.MediaType()
	if err != nil {
		return nil, err
	}
	newAnnotations, err := newSig.Annotations()
	if err != nil {
		return nil, err
	}

	sigs, err := sigImage.Get()
	if err != nil {
		return nil, err
	}

LayerLoop:
	for _, sig := range sigs {
		existingAnnotations, err := sig.Annotations()
		if err != nil {
			continue LayerLoop
		}
		// if there are any new annotations, then this isn't a duplicate
		for a, value := range newAnnotations {
			if val, ok := existingAnnotations[a]; !ok || val != value {
				continue LayerLoop
			}
		}
		if existingDigest, err := sig.Digest(); err != nil || existingDigest != newDigest {
			continue LayerLoop
		}
		if existingMediaType, err := sig.MediaType(); err != nil || existingMediaType != newMediaType {
			continue LayerLoop
		}

		existingSignature, err := sig.Base64Signature()
		if err != nil || existingSignature == "" {
			continue LayerLoop
		}
		uploadedSig, err := base64.StdEncoding.DecodeString(existingSignature)
		if err != nil {
			continue LayerLoop
		}
		r, err := newSig.Uncompressed()
		if err != nil {
			return nil, err
		}
		if err := dupeDetector.VerifySignature(bytes.NewReader(uploadedSig), r); err == nil {
			// An equivalent signature has already been uploaded.
			return uploadedSig, nil
		}
	}
	return nil, nil
}

type UploadOpts struct {
	Cert                  []byte
	Chain                 []byte
	DupeDetector          signature.Verifier
	Bundle                *oci.Bundle
	AdditionalAnnotations map[string]string
	RemoteOpts            []remote.Option
	MediaType             string
}

func UploadSignature(signature, payload []byte, dst name.Reference, opts UploadOpts) error {
	b64sig := base64.StdEncoding.EncodeToString(signature)
	l := &staticLayer{
		b:  payload,
		mt: ctypes.SimpleSigningMediaType,
		annotations: kmeta.UnionMaps(opts.AdditionalAnnotations, map[string]string{
			sigkey: b64sig,
		}),
		b64sig:   b64sig,
		certPEM:  string(opts.Cert),
		chainPEM: string(opts.Chain),
		bundle:   opts.Bundle,
	}
	// Preserve the default
	if opts.MediaType != "" {
		l.mt = types.MediaType(opts.MediaType)
	}

	if opts.Cert != nil {
		l.annotations[certkey] = l.certPEM
		l.annotations[chainkey] = l.chainPEM
	}
	if opts.Bundle != nil {
		b, err := swag.WriteJSON(opts.Bundle)
		if err != nil {
			return errors.Wrap(err, "marshaling bundle")
		}
		l.annotations[BundleKey] = string(b)
	}

	base, err := SignatureImage(dst, opts.RemoteOpts...)
	if err != nil {
		return err
	}

	if opts.DupeDetector != nil {
		if uploadedSig, err := findDuplicate(base, l, opts.DupeDetector); err != nil || uploadedSig != nil {
			return err
		}
	}

	img, err := mutate.Append(base, mutate.Addendum{
		Layer:       l,
		Annotations: l.annotations,
	})
	if err != nil {
		return err
	}

	return remote.Write(dst, img, opts.RemoteOpts...)
}

type staticLayer struct {
	b           []byte
	mt          types.MediaType
	annotations map[string]string
	b64sig      string
	certPEM     string
	chainPEM    string
	bundle      *oci.Bundle
}

var _ v1.Layer = (*staticLayer)(nil)
var _ oci.Signature = (*staticLayer)(nil)

// Annotations implements oci.Signature
func (l *staticLayer) Annotations() (map[string]string, error) {
	return l.annotations, nil
}

// Payload implements oci.Signature
func (l *staticLayer) Payload() ([]byte, error) {
	return l.b, nil
}

// Base64Signature implements oci.Signature
func (l *staticLayer) Base64Signature() (string, error) {
	return l.b64sig, nil
}

// Cert implements oci.Signature
func (l *staticLayer) Cert() (*x509.Certificate, error) {
	certs, err := cryptoutils.LoadCertificatesFromPEM(strings.NewReader(l.certPEM))
	if err != nil {
		return nil, err
	}
	return certs[0], nil
}

// Chain implements oci.Signature
func (l *staticLayer) Chain() ([]*x509.Certificate, error) {
	certs, err := cryptoutils.LoadCertificatesFromPEM(strings.NewReader(l.chainPEM))
	if err != nil {
		return nil, err
	}
	return certs, nil
}

// Bundle implements oci.Signature
func (l *staticLayer) Bundle() (*oci.Bundle, error) {
	return l.bundle, nil
}

// Digest implements v1.Layer
func (l *staticLayer) Digest() (v1.Hash, error) {
	h, _, err := v1.SHA256(bytes.NewReader(l.b))
	return h, err
}

// DiffID implements v1.Layer
func (l *staticLayer) DiffID() (v1.Hash, error) {
	h, _, err := v1.SHA256(bytes.NewReader(l.b))
	return h, err
}

// Compressed implements v1.Layer
func (l *staticLayer) Compressed() (io.ReadCloser, error) {
	return ioutil.NopCloser(bytes.NewReader(l.b)), nil
}

// Uncompressed implements v1.Layer
func (l *staticLayer) Uncompressed() (io.ReadCloser, error) {
	return ioutil.NopCloser(bytes.NewReader(l.b)), nil
}

// Size implements v1.Layer
func (l *staticLayer) Size() (int64, error) {
	return int64(len(l.b)), nil
}

// MediaType implements v1.Layer
func (l *staticLayer) MediaType() (types.MediaType, error) {
	return l.mt, nil
}
