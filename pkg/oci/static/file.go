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

package static

import (
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/cosign/pkg/oci/signed"
)

// NewFile constructs a new v1.Image with the provided payload.
func NewFile(payload []byte, opts ...Option) (oci.File, error) {
	o, err := makeOptions(opts...)
	if err != nil {
		return nil, err
	}
	base := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
	base = mutate.ConfigMediaType(base, o.ConfigMediaType)
	img, err := mutate.Append(base, mutate.Addendum{
		Layer: &staticLayer{
			b:    payload,
			opts: o,
		},
	})
	if err != nil {
		return nil, err
	}
	return signed.Image(img), nil
}
