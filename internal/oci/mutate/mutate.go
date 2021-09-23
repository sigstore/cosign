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

package mutate

import (
	"errors"
	"fmt"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/sigstore/cosign/internal/oci"
	"github.com/sigstore/cosign/internal/oci/empty"
	"github.com/sigstore/cosign/internal/oci/signed"
)

// Appendable is our signed version of mutate.Appendable
type Appendable interface {
	oci.SignedEntity
	mutate.Appendable
}

// IndexAddendum is our signed version of mutate.IndexAddendum
type IndexAddendum struct {
	Add Appendable
	v1.Descriptor
}

// AppendManifests is a form of mutate.AppendManifests that produces an
// oci.SignedImageIndex.  The index itself will contain no signatures,
// but allows access to the contained signed entities.
func AppendManifests(base v1.ImageIndex, adds ...IndexAddendum) oci.SignedImageIndex {
	madds := make([]mutate.IndexAddendum, 0, len(adds))
	for _, add := range adds {
		madds = append(madds, mutate.IndexAddendum{
			Add:        add.Add,
			Descriptor: add.Descriptor,
		})
	}
	return &indexWrapper{
		v1Index:  mutate.AppendManifests(base, madds...),
		ogbase:   base,
		addendum: adds,
	}
}

// We alias ImageIndex so that we can inline it without the type
// name colliding with the name of a method it had to implement.
type v1Index v1.ImageIndex

type indexWrapper struct {
	v1Index
	ogbase   v1Index
	addendum []IndexAddendum
}

var _ oci.SignedImageIndex = (*indexWrapper)(nil)

// Signatures implements oic.SignedImageIndex
func (i *indexWrapper) Signatures() (oci.Signatures, error) {
	return empty.Signatures(), nil
}

// Attestations implements oic.SignedImageIndex
func (i *indexWrapper) Attestations() (oci.Attestations, error) {
	// TODO(mattmoor): return empty image
	return nil, errors.New("NYI")
}

// SignedImage implements oic.SignedImageIndex
func (i *indexWrapper) SignedImage(h v1.Hash) (oci.SignedImage, error) {
	for _, add := range i.addendum {
		si, ok := add.Add.(oci.SignedImage)
		if !ok {
			continue
		}
		if d, err := si.Digest(); err != nil {
			return nil, err
		} else if d == h {
			return si, nil
		}
	}
	if sb, ok := i.ogbase.(oci.SignedImageIndex); ok {
		return sb.SignedImage(h)
	} else if unsigned, err := i.Image(h); err != nil {
		return nil, err
	} else {
		return signed.Image(unsigned), nil
	}
}

// SignedImageIndex implements oic.SignedImageIndex
func (i *indexWrapper) SignedImageIndex(h v1.Hash) (oci.SignedImageIndex, error) {
	for _, add := range i.addendum {
		sii, ok := add.Add.(oci.SignedImageIndex)
		if !ok {
			continue
		}
		if d, err := sii.Digest(); err != nil {
			return nil, err
		} else if d == h {
			return sii, nil
		}
	}
	if sb, ok := i.ogbase.(oci.SignedImageIndex); ok {
		return sb.SignedImageIndex(h)
	} else if unsigned, err := i.ImageIndex(h); err != nil {
		return nil, err
	} else {
		return signed.ImageIndex(unsigned), nil
	}
}

// AttachSignatureToEntity attaches the provided signature to the provided entity.
func AttachSignatureToEntity(se oci.SignedEntity, sig oci.Signature, opts ...SignOption) (oci.SignedEntity, error) {
	switch obj := se.(type) {
	case oci.SignedImage:
		return AttachSignatureToImage(obj, sig, opts...)
	case oci.SignedImageIndex:
		return AttachSignatureToImageIndex(obj, sig, opts...)
	default:
		return nil, fmt.Errorf("unsupported type: %T", se)
	}
}

// AttachSignatureToImage attaches the provided signature to the provided image.
func AttachSignatureToImage(si oci.SignedImage, sig oci.Signature, opts ...SignOption) (oci.SignedImage, error) {
	return &signedImage{
		SignedImage: si,
		sig:         sig,
		so:          makeSignOpts(opts...),
	}, nil
}

type signedImage struct {
	oci.SignedImage
	sig oci.Signature
	so  *signOpts
}

// Signatures implements oci.SignedImage
func (si *signedImage) Signatures() (oci.Signatures, error) {
	base, err := si.SignedImage.Signatures()
	if err != nil {
		return nil, err
	}
	if si.so.dd != nil {
		if existing, err := si.so.dd.Find(base, si.sig); err != nil {
			return nil, err
		} else if existing != nil {
			// Just return base if the signature is redundant
			return base, nil
		}
	}
	return AppendSignatures(base, si.sig)
}

// AttachSignatureToImageIndex attaches the provided signature to the provided image index.
func AttachSignatureToImageIndex(sii oci.SignedImageIndex, sig oci.Signature, opts ...SignOption) (oci.SignedImageIndex, error) {
	return &signedImageIndex{
		ociSignedImageIndex: sii,
		sig:                 sig,
		so:                  makeSignOpts(opts...),
	}, nil
}

type ociSignedImageIndex oci.SignedImageIndex

type signedImageIndex struct {
	ociSignedImageIndex
	sig oci.Signature
	so  *signOpts
}

// Signatures implements oci.SignedImageIndex
func (sii *signedImageIndex) Signatures() (oci.Signatures, error) {
	base, err := sii.ociSignedImageIndex.Signatures()
	if err != nil {
		return nil, err
	}
	if sii.so.dd != nil {
		if existing, err := sii.so.dd.Find(base, sii.sig); err != nil {
			return nil, err
		} else if existing != nil {
			// Just return base if the signature is redundant
			return base, nil
		}
	}
	return AppendSignatures(base, sii.sig)
}
