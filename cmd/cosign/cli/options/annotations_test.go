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

package options

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/sigstore/cosign/v2/pkg/signature"
)

func TestAnnotationOptions_AnnotationsMap(t *testing.T) {
	tests := []struct {
		name        string
		annotations []string
		want        signature.AnnotationsMap
		wantErr     bool
	}{{
		name: "nil",
	}, {
		name:        "valid key",
		annotations: []string{"key=value"},
		want: signature.AnnotationsMap{
			Annotations: map[string]interface{}{
				"key": "value",
			},
		},
	}, {
		name:        "invalid key",
		annotations: []string{"key value"},
		wantErr:     true,
		want:        signature.AnnotationsMap{},
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &AnnotationOptions{
				Annotations: tt.annotations,
			}
			got, err := s.AnnotationsMap()
			if (err != nil) != tt.wantErr {
				t.Errorf("AnnotationsMap() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Errorf("AnnotationsMap() got = %v, want %v\n diff: %s", got, tt.want, diff)
			}
		})
	}
}
