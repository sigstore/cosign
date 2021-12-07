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
			`FROM index.docker.io/library/alpine@sha256:100448e45467d4f3838fc8d95faab2965e22711b6edf67bbd8ec9c07f612b553
`,
			false,
		},
		{
			"happy alpine trim",
			`   FROM    alpine:3.13   `,
			`FROM    index.docker.io/library/alpine@sha256:100448e45467d4f3838fc8d95faab2965e22711b6edf67bbd8ec9c07f612b553
`,
			false,
		},
		{
			"happy alpine copy",
			`FROM alpine:3.13
COPY --from=alpine:3.13
`,
			`FROM index.docker.io/library/alpine@sha256:100448e45467d4f3838fc8d95faab2965e22711b6edf67bbd8ec9c07f612b553
COPY --from=index.docker.io/library/alpine@sha256:100448e45467d4f3838fc8d95faab2965e22711b6edf67bbd8ec9c07f612b553
`,
			false,
		},
		{
			"alpine with digest",
			`FROM alpine@sha256:100448e45467d4f3838fc8d95faab2965e22711b6edf67bbd8ec9c07f612b553`,
			`FROM alpine@sha256:100448e45467d4f3838fc8d95faab2965e22711b6edf67bbd8ec9c07f612b553
`,
			false,
		},
		{
			"multi-line",
			`FROM alpine:3.13
COPY . .

RUN ls`,
			`FROM index.docker.io/library/alpine@sha256:100448e45467d4f3838fc8d95faab2965e22711b6edf67bbd8ec9c07f612b553
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
			`FROM index.docker.io/library/alpine@sha256:100448e45467d4f3838fc8d95faab2965e22711b6edf67bbd8ec9c07f612b553
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
		{
			"should not break for invalid --from image reference",
			`FROM golang:latest AS builder
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app .

FROM alpine:latest
WORKDIR /root/
COPY --from=builder /go/src/github.com/foo/bar/app .
CMD ["./app"]`,
			`FROM index.docker.io/library/golang@sha256:27ff940e5e460ef6dc80311c7bb9c633871bb99a1f45e190fa29864a1ea7209a AS builder
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app .

FROM index.docker.io/library/alpine@sha256:bc41182d7ef5ffc53a40b044e725193bc10142a1243f395ee852a8d9730fc2ad
WORKDIR /root/
COPY --from=builder /go/src/github.com/foo/bar/app .
CMD ["./app"]
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
