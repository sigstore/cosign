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
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/internal/oci"
)

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
