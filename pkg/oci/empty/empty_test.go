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
	"os"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/sigstore/cosign/pkg/cosign/env"
)

func TestEmptyImage(t *testing.T) {
	tests := []struct {
		name         string
		value        string
		wantMT       types.MediaType
		wantConfigMT types.MediaType
	}{{
		name:         "unset",
		wantMT:       types.OCIManifestSchema1,
		wantConfigMT: types.OCIConfigJSON,
	}, {
		name:         "set false",
		value:        "false",
		wantMT:       types.OCIManifestSchema1,
		wantConfigMT: types.OCIConfigJSON,
	}, {
		name:         "set true",
		value:        "true",
		wantMT:       types.DockerManifestSchema2,
		wantConfigMT: types.DockerConfigJSON,
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := os.Setenv(env.VariableDockerMediaTypes.String(), test.value); err != nil {
				t.Fatalf("Setenv() = %v", err)
			}

			img := Signatures()

			if mt, err := img.MediaType(); err != nil {
				t.Errorf("MediaType() = %v", err)
			} else if mt != test.wantMT {
				t.Errorf("MediaType() = %v, wanted %v", mt, test.wantMT)
			}

			m, err := img.Manifest()
			if err != nil {
				t.Fatalf("ConfigFile() = %v", err)
			}

			if mt := m.Config.MediaType; mt != test.wantConfigMT {
				t.Errorf("Config.MediaType = %v, wanted %v", mt, test.wantConfigMT)
			}
		})
	}
}
