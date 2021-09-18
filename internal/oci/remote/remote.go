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
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/internal/oci"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

const (
	sigkey    = "dev.cosignproject.cosign/signature"
	certkey   = "dev.sigstore.cosign/certificate"
	chainkey  = "dev.sigstore.cosign/chain"
	BundleKey = "dev.sigstore.cosign/bundle"
)

// These enable mocking for unit testing without faking an entire registry.
var (
	remoteImage = remote.Image
	remoteIndex = remote.Index
	remoteGet   = remote.Get
)

// SignedEntity provides access to a remote reference, and its signatures.
// The SignedEntity will be one of SignedImage or SignedImageIndex.
func SignedEntity(ref name.Reference, options ...Option) (oci.SignedEntity, error) {
	o, err := makeOptions(ref.Context(), options...)
	if err != nil {
		return nil, err
	}

	got, err := remoteGet(ref, o.ROpt...)
	if err != nil {
		return nil, err
	}

	switch got.MediaType {
	case types.OCIImageIndex, types.DockerManifestList:
		ii, err := got.ImageIndex()
		if err != nil {
			return nil, err
		}
		return &index{
			v1Index: ii,
			ref:     ref.Context().Digest(got.Digest.String()),
			opt:     o,
		}, nil

	case types.OCIManifestSchema1, types.DockerManifestSchema2:
		i, err := got.Image()
		if err != nil {
			return nil, err
		}
		return &image{
			Image: i,
			opt:   o,
		}, nil

	default:
		return nil, fmt.Errorf("unknown mime type: %v", got.MediaType)
	}
}

// SignedImageIndex provides access to a remote index reference, and its signatures.
func SignedImageIndex(ref name.Reference, options ...Option) (oci.SignedImageIndex, error) {
	o, err := makeOptions(ref.Context(), options...)
	if err != nil {
		return nil, err
	}
	ri, err := remoteIndex(ref, o.ROpt...)
	if err != nil {
		return nil, err
	}
	return &index{
		v1Index: ri,
		ref:     ref,
		opt:     o,
	}, nil
}

// We alias ImageIndex so that we can inline it without the type
// name colliding with the name of a method it had to implement.
type v1Index v1.ImageIndex

type index struct {
	v1Index
	ref name.Reference
	opt *options
}

var _ oci.SignedImageIndex = (*index)(nil)

func normalize(h v1.Hash, suffix string) string {
	// sha256:d34db33f -> sha256-d34db33f.suffix
	return strings.ReplaceAll(h.String(), ":", "-") + suffix
}

// signatures is a shared implementation of the oci.Signed* Signatures method.
func signatures(digestable interface{ Digest() (v1.Hash, error) }, o *options) (oci.Signatures, error) {
	h, err := digestable.Digest()
	if err != nil {
		return nil, err
	}
	return Signatures(o.TargetRepository.Tag(normalize(h, o.SignatureSuffix)), o.ROpt...)
}

// Signatures implements oic.SignedImageIndex
func (i *index) Signatures() (oci.Signatures, error) {
	return signatures(i, i.opt)
}

// Attestations implements oic.SignedImageIndex
func (i *index) Attestations() (oci.Attestations, error) {
	// TODO(mattmoor): allow accessing attestations.
	return nil, errors.New("NYI")
}

// SignedImage implements oic.SignedImageIndex
func (i *index) SignedImage(h v1.Hash) (oci.SignedImage, error) {
	img, err := i.Image(h)
	if err != nil {
		return nil, err
	}
	return &image{
		Image: img,
		opt:   i.opt,
	}, nil
}

// SignedImageIndex implements oic.SignedImageIndex
func (i *index) SignedImageIndex(h v1.Hash) (oci.SignedImageIndex, error) {
	ii, err := i.ImageIndex(h)
	if err != nil {
		return nil, err
	}
	return &index{
		v1Index: ii,
		opt:     i.opt,
	}, nil
}

// SignedImage provides access to a remote image reference, and its signatures.
func SignedImage(ref name.Reference, options ...Option) (oci.SignedImage, error) {
	o, err := makeOptions(ref.Context(), options...)
	if err != nil {
		return nil, err
	}
	ri, err := remoteImage(ref, o.ROpt...)
	if err != nil {
		return nil, err
	}
	return &image{
		Image: ri,
		opt:   o,
	}, nil
}

type image struct {
	v1.Image
	opt *options
}

var _ oci.SignedImage = (*image)(nil)

// Signatures implements oic.SignedImage
func (i *image) Signatures() (oci.Signatures, error) {
	return signatures(i, i.opt)
}

// Attestations implements oic.SignedImage
func (i *image) Attestations() (oci.Attestations, error) {
	// TODO(mattmoor): allow accessing attestations.
	return nil, errors.New("NYI")
}

// Signatures fetches the signatures image represented by the named reference.
// TODO(mattmoor): Consider changing to take our Options
func Signatures(ref name.Reference, opts ...remote.Option) (oci.Signatures, error) {
	img, err := remoteImage(ref, opts...)
	if err != nil {
		return nil, err
	}
	return &sigs{
		Image: img,
	}, nil
}

type sigs struct {
	v1.Image
}

var _ oci.Signatures = (*sigs)(nil)

// Get implements oci.Signatures
func (s *sigs) Get() ([]oci.Signature, error) {
	m, err := s.Manifest()
	if err != nil {
		return nil, err
	}
	signatures := make([]oci.Signature, 0, len(m.Layers))
	for _, desc := range m.Layers {
		layer, err := s.Image.LayerByDigest(desc.Digest)
		if err != nil {
			return nil, err
		}
		signatures = append(signatures, &sigLayer{
			Layer: layer,
			img:   s,
			desc:  desc,
		})
	}
	return signatures, nil
}

type sigLayer struct {
	v1.Layer
	img  *sigs
	desc v1.Descriptor
}

var _ oci.Signature = (*sigLayer)(nil)

// Payload implements oci.Signature
func (s *sigLayer) Payload() ([]byte, error) {
	l, err := s.img.LayerByDigest(s.desc.Digest)
	if err != nil {
		return nil, err
	}

	// Compressed is a misnomer here, we just want the raw bytes from the registry.
	r, err := l.Compressed()
	if err != nil {
		return nil, err
	}
	payload, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return payload, nil
}

// Base64Signature implements oci.Signature
func (s *sigLayer) Base64Signature() (string, error) {
	b64sig, ok := s.desc.Annotations[sigkey]
	if !ok {
		return "", fmt.Errorf("signature layer %s is missing %q annotation", s.desc.Digest, sigkey)
	}
	return b64sig, nil
}

// Cert implements oci.Signature
func (s *sigLayer) Cert() (*x509.Certificate, error) {
	certPEM := s.desc.Annotations[certkey]
	if certPEM == "" {
		return nil, nil
	}
	certs, err := cryptoutils.LoadCertificatesFromPEM(strings.NewReader(certPEM))
	if err != nil {
		return nil, err
	}
	return certs[0], nil
}

// Chain implements oci.Signature
func (s *sigLayer) Chain() ([]*x509.Certificate, error) {
	chainPEM := s.desc.Annotations[chainkey]
	if chainPEM == "" {
		return nil, nil
	}
	certs, err := cryptoutils.LoadCertificatesFromPEM(strings.NewReader(chainPEM))
	if err != nil {
		return nil, err
	}
	return certs, nil
}

// Bundle implements oci.Signature
func (s *sigLayer) Bundle() (*oci.Bundle, error) {
	bundle := s.desc.Annotations[BundleKey]
	if bundle == "" {
		return nil, nil
	}
	var b oci.Bundle
	if err := json.Unmarshal([]byte(bundle), &b); err != nil {
		return nil, errors.Wrap(err, "unmarshaling bundle")
	}
	return &b, nil
}
