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
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/internal/oci"
)

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
