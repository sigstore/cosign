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
