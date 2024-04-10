// Copyright 2024 The Sigstore Authors.
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
	"errors"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/fake"
)

func TestGet(t *testing.T) {
	tests := []struct {
		name      string
		layers    int
		wantError error
	}{
		{
			name:      "within limit",
			layers:    23,
			wantError: nil,
		},
		{
			name:      "exceeds limit",
			layers:    4242,
			wantError: errors.New("number of layers (4242) exceeded the limit (1000)"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := sigs{
				Image: &fake.FakeImage{
					ManifestStub: func() (*v1.Manifest, error) {
						return &v1.Manifest{
							Layers: make([]v1.Descriptor, test.layers),
						}, nil
					},
				},
			}
			_, err := s.Get()
			if test.wantError != nil && test.wantError.Error() != err.Error() {
				t.Fatalf("Get() = %v, wanted %v", err, test.wantError)
			}
			if test.wantError == nil && err != nil {
				t.Fatalf("Get() = %v, wanted %v", err, test.wantError)
			}
		})
	}
}
