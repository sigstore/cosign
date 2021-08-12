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
	"reflect"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func TestFileFromFlag(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want File
	}{
		{
			name: "plain",
			s:    "foo",
			want: &file{path: "foo"},
		},
		{
			name: "os",
			s:    "foo:darwin",
			want: &file{path: "foo", platform: &v1.Platform{
				OS: "darwin",
			}},
		},
		{
			name: "os",
			s:    "foo:darwin/amd64",
			want: &file{path: "foo", platform: &v1.Platform{
				OS:           "darwin",
				Architecture: "amd64",
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FileFromFlag(tt.s); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("fileFromFlag() = %v, want %v", got, tt.want)
			}
		})
	}
}
