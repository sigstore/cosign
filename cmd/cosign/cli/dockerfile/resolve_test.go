// Copyright 2021 The Sigstore Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dockerfile

import (
	"bytes"
	"reflect"
	"testing"
)

func Test_resolveDigest(t *testing.T) {
	tests := []struct {
		name       string
		dockerfile string
		want       string
		wantErr    bool
	}{
		{
			"happy alpine",
			`FROM alpine:3.13`,
			`FROM index.docker.io/library/alpine@sha256:026f721af4cf2843e07bba648e158fb35ecc876d822130633cc49f707f0fc88c
`,
			false,
		},
		{
			"alpine with digest",
			`FROM alpine@sha256:026f721af4cf2843e07bba648e158fb35ecc876d822130633cc49f707f0fc88c`,
			`FROM alpine@sha256:026f721af4cf2843e07bba648e158fb35ecc876d822130633cc49f707f0fc88c
`,
			false,
		},
		{
			"multi-line",
			`FROM alpine:3.13
COPY . .

RUN ls`,
			`FROM index.docker.io/library/alpine@sha256:026f721af4cf2843e07bba648e158fb35ecc876d822130633cc49f707f0fc88c
COPY . .

RUN ls
`,
			false,
		},
		{
			"skip scratch",
			`FROM alpine:3.13
FROM scratch
RUN ls`,
			`FROM index.docker.io/library/alpine@sha256:026f721af4cf2843e07bba648e158fb35ecc876d822130633cc49f707f0fc88c
FROM scratch
RUN ls
`,
			false,
		},
		{
			"should not break invalid image ref",
			`FROM alpine:$(TAG)
FROM $(IMAGE)
`,
			`FROM alpine:$(TAG)
FROM $(IMAGE)
`,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveDigest(bytes.NewBuffer([]byte(tt.dockerfile)))
			if (err != nil) != tt.wantErr {
				t.Errorf("resolveDigest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(string(got), tt.want) {
				t.Errorf("resolveDigest() got = %v, want %v", string(got), tt.want)
			}
		})
	}
}
