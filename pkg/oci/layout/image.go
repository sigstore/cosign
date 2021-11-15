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
	"github.com/sigstore/cosign/pkg/oci/internal/signature"
)

// SignedImage provides access to a remote image reference, and its signatures.
func SignedImage(path string) (oci.SignedImage, error) {
	p, err := layout.FromPath(imagePath(path))
	if err != nil {
		return nil, err
	}
	// there should only be one image in the index, so we can pass in empty hash to get it
	img, err := p.Image(v1.Hash{})
	if err != nil {
		return nil, err
	}

	return &image{
		Image: img,
		path:  path,
	}, nil
}

type image struct {
	path string
	v1.Image
}

var _ oci.SignedImage = (*image)(nil)

type sigs struct {
	v1.Image
}

var _ oci.Signatures = (*sigs)(nil)

// Get implements oci.Signatures
func (s *sigs) Get() ([]oci.Signature, error) {
	manifest, err := s.Image.Manifest()
	if err != nil {
		return nil, err
	}
	signatures := make([]oci.Signature, 0, len(manifest.Layers))
	for _, desc := range manifest.Layers {
		l, err := s.Image.LayerByDigest(desc.Digest)
		if err != nil {
			return nil, err
		}
		signatures = append(signatures, signature.New(l, desc))
	}
	return signatures, nil
}

// Signatures implements oci.SignedImage
func (i *image) Signatures() (oci.Signatures, error) {
	sigPath, err := layout.FromPath(signaturesPath(i.path))
	if err != nil {
		return nil, err
	}
	// there should only be one image in the index, so we can pass in empty hash to get it
	img, err := sigPath.Image(v1.Hash{})
	if err != nil {
		return nil, err
	}
	return &sigs{
		Image: img,
	}, nil
}

// Attestations implements oci.SignedImage
// TODO (priyawadhwa@)
func (i *image) Attestations() (oci.Signatures, error) {
	return nil, fmt.Errorf("not yet implemented")
}

// Attestations implements oci.SignedImage
// TODO (priyawadhwa@)
func (i *image) Attachment(name string) (oci.File, error) {
	return nil, fmt.Errorf("not yet implemented")
}
