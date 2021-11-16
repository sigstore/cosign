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

package layout

import (
	"fmt"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/cosign/pkg/oci/signed"
)

const (
	imageAnnotation = "dev.cosignproject.cosign/image"
	sigsAnnotation  = "dev.cosignproject.cosign/sigs"
)

// SignedImageIndex provides access to a local index reference, and its signatures.
func SignedImageIndex(path string) (oci.SignedImageIndex, error) {
	p, err := layout.FromPath(path)
	if err != nil {
		return nil, err
	}
	ii, err := p.ImageIndex()
	if err != nil {
		return nil, err
	}
	return &index{
		v1Index: ii,
	}, nil
}

// We alias ImageIndex so that we can inline it without the type
// name colliding with the name of a method it had to implement.
type v1Index v1.ImageIndex

type index struct {
	v1Index
}

var _ oci.SignedImageIndex = (*index)(nil)

// Signatures implements oci.SignedImageIndex
func (i *index) Signatures() (oci.Signatures, error) {
	sigsImage, err := i.imageByAnnotation(sigsAnnotation)
	if err != nil {
		return nil, err
	}
	return &sigs{sigsImage}, nil
}

// Attestations implements oci.SignedImageIndex
func (i *index) Attestations() (oci.Signatures, error) {
	return nil, fmt.Errorf("not yet implemented")
}

// Attestations implements oci.SignedImage
func (i *index) Attachment(name string) (oci.File, error) {
	return nil, fmt.Errorf("not yet implemented")
}

// SignedImage implements oci.SignedImageIndex
func (i *index) SignedImage(h v1.Hash) (oci.SignedImage, error) {
	img, err := i.Image(h)
	if err != nil {
		return nil, err
	}
	return signed.Image(img), nil
}

// imageByAnnotation searches through all manifests in the index.json
// and returns the image that has the matching annotation
func (i *index) imageByAnnotation(annotation string) (v1.Image, error) {
	manifest, err := i.IndexManifest()
	if err != nil {
		return nil, err
	}
	for _, m := range manifest.Manifests {
		if _, ok := m.Annotations[annotation]; ok {
			img, err := i.Image(m.Digest)
			if err != nil {
				return nil, err
			}
			return img, nil
		}
	}
	return nil, fmt.Errorf("unable to find image")
}

// SignedImageIndex implements oci.SignedImageIndex
func (i *index) SignedImageIndex(h v1.Hash) (oci.SignedImageIndex, error) {
	ii, err := i.ImageIndex(h)
	if err != nil {
		return nil, err
	}
	return &index{
		v1Index: ii,
	}, nil
}
