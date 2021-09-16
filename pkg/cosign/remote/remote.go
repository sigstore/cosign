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
	"encoding/base64"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/go-openapi/swag"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/pkg/errors"

	"github.com/sigstore/cosign/internal/oci"
	"github.com/sigstore/cosign/internal/oci/empty"
	ctypes "github.com/sigstore/cosign/pkg/types"
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
func SignatureImage(ref name.Reference, opts ...remote.Option) (v1.Image, error) {
	base, err := remote.Image(ref, opts...)
	if err == nil {
		return base, nil
	}
	var te *transport.Error
	if errors.As(err, &te) {
		if te.StatusCode != http.StatusNotFound {
			return nil, te
		}
		return empty.Image(), nil
	}
	return nil, err
}

func findDuplicate(sigImage v1.Image, payload []byte, dupeDetector signature.Verifier, annotations map[string]string) ([]byte, error) {
	l := &staticLayer{
		b:  payload,
		mt: ctypes.SimpleSigningMediaType,
	}

	sigDigest, err := l.Digest()
	if err != nil {
		return nil, err
	}
	manifest, err := sigImage.Manifest()
	if err != nil {
		return nil, err
	}

LayerLoop:
	for _, layer := range manifest.Layers {
		// if there are any new annotations, then this isn't a duplicate
		for a, value := range annotations {
			if val, ok := layer.Annotations[a]; !ok || val != value {
				continue LayerLoop
			}
		}
		if layer.MediaType == ctypes.SimpleSigningMediaType && layer.Digest == sigDigest && layer.Annotations[sigkey] != "" {
			uploadedSig, err := base64.StdEncoding.DecodeString(layer.Annotations[sigkey])
			if err != nil {
				return nil, err
			}
			if err := dupeDetector.VerifySignature(bytes.NewReader(uploadedSig), bytes.NewReader(payload)); err == nil {
				// An equivalent signature has already been uploaded.
				return uploadedSig, nil
			}
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

func UploadSignature(signature, payload []byte, dst name.Reference, opts UploadOpts) (uploadedSig []byte, err error) {
	// Preserve the default
	if opts.MediaType == "" {
		opts.MediaType = ctypes.SimpleSigningMediaType
	}
	l := &staticLayer{
		b:  payload,
		mt: types.MediaType(opts.MediaType),
	}

	base, err := SignatureImage(dst, opts.RemoteOpts...)
	if err != nil {
		return nil, err
	}

	if opts.DupeDetector != nil {
		if uploadedSig, err = findDuplicate(base, payload, opts.DupeDetector, opts.AdditionalAnnotations); err != nil || uploadedSig != nil {
			return uploadedSig, err
		}
	}

	annotations := map[string]string{
		sigkey: base64.StdEncoding.EncodeToString(signature),
	}
	if opts.Cert != nil {
		annotations[certkey] = string(opts.Cert)
		annotations[chainkey] = string(opts.Chain)
	}
	if opts.Bundle != nil {
		b, err := swag.WriteJSON(opts.Bundle)
		if err != nil {
			return nil, errors.Wrap(err, "marshaling bundle")
		}
		annotations[BundleKey] = string(b)
	}
	img, err := mutate.Append(base, mutate.Addendum{
		Layer:       l,
		Annotations: annotations,
	})
	if err != nil {
		return nil, err
	}

	if err := remote.Write(dst, img, opts.RemoteOpts...); err != nil {
		return nil, err
	}
	return signature, nil
}

type staticLayer struct {
	b  []byte
	mt types.MediaType
}

func (l *staticLayer) Digest() (v1.Hash, error) {
	h, _, err := v1.SHA256(bytes.NewReader(l.b))
	return h, err
}

// DiffID returns the Hash of the uncompressed layer.
func (l *staticLayer) DiffID() (v1.Hash, error) {
	h, _, err := v1.SHA256(bytes.NewReader(l.b))
	return h, err
}

// Compressed returns an io.ReadCloser for the compressed layer contents.
func (l *staticLayer) Compressed() (io.ReadCloser, error) {
	return ioutil.NopCloser(bytes.NewReader(l.b)), nil
}

// Uncompressed returns an io.ReadCloser for the uncompressed layer contents.
func (l *staticLayer) Uncompressed() (io.ReadCloser, error) {
	return ioutil.NopCloser(bytes.NewReader(l.b)), nil
}

// Size returns the compressed size of the Layer.
func (l *staticLayer) Size() (int64, error) {
	return int64(len(l.b)), nil
}

// MediaType returns the media type of the Layer.
func (l *staticLayer) MediaType() (types.MediaType, error) {
	return l.mt, nil
}
