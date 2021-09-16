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

package empty

import (
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/cosign/internal/oci"
)

// Image constructs an empty image on which to base signature images.
func Image() v1.Image {
	base := empty.Image
	if !oci.DockerMediaTypes() {
		base = mutate.MediaType(base, types.OCIManifestSchema1)
		m, err := base.Manifest()
		if err != nil {
			// It is impossible for this to happen.
			panic(err.Error())
		}
		m.Config.MediaType = types.OCIConfigJSON
	}
	return base
}
