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

package cli

import (
	"reflect"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	cremote "github.com/sigstore/cosign/pkg/cosign/remote"
)

func Test_fileFromFlag(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want cremote.File
	}{
		{
			name: "plain",
			s:    "foo",
			want: cremote.File{Path: "foo"},
		},
		{
			name: "os",
			s:    "foo:darwin",
			want: cremote.File{Path: "foo", Platform: &v1.Platform{
				OS: "darwin",
			}},
		},
		{
			name: "os",
			s:    "foo:darwin/amd64",
			want: cremote.File{Path: "foo", Platform: &v1.Platform{
				OS:           "darwin",
				Architecture: "amd64",
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := fileFromFlag(tt.s); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("fileFromFlag() = %v, want %v", got, tt.want)
			}
		})
	}
}
