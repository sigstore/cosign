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
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

func TestTagMethods(t *testing.T) {
	rg := remoteGet
	defer func() {
		remoteGet = rg
	}()
	remoteGet = func(_ name.Reference, _ ...remote.Option) (*remote.Descriptor, error) {
		return &remote.Descriptor{
			Descriptor: v1.Descriptor{
				Digest: v1.Hash{
					Algorithm: "sha256",
					// As of 2021-09-20:
					// crane digest gcr.io/distroless/static:nonroot
					Hex: "be5d77c62dbe7fedfb0a4e5ec2f91078080800ab1f18358e5f31fcc8faa023c4",
				},
			},
		}, nil
	}

	tests := []struct {
		name string
		fn   func(name.Reference, ...Option) (name.Tag, error)
		ref  name.Reference
		opts []Option
		want name.Reference // Always a tag, but shorter to write things.
	}{{
		name: "signature passed a tag",
		fn:   SignatureTag,
		ref:  name.MustParseReference("gcr.io/distroless/static:nonroot"),
		want: name.MustParseReference("gcr.io/distroless/static:sha256-be5d77c62dbe7fedfb0a4e5ec2f91078080800ab1f18358e5f31fcc8faa023c4.sig"),
	}, {
		name: "signature passed a tag (w/ custom suffix)",
		fn:   SignatureTag,
		ref:  name.MustParseReference("gcr.io/distroless/static:nonroot"),
		opts: []Option{WithSignatureSuffix("snowflake")},
		want: name.MustParseReference("gcr.io/distroless/static:sha256-be5d77c62dbe7fedfb0a4e5ec2f91078080800ab1f18358e5f31fcc8faa023c4.snowflake"),
	}, {
		name: "signature passed a digest",
		fn:   SignatureTag,
		ref:  name.MustParseReference("gcr.io/distroless/static@sha256:be5d77c62dbe7fedfb0a4e5ec2f91078080800ab1f18358e5f31fcc8faa023c4"),
		want: name.MustParseReference("gcr.io/distroless/static:sha256-be5d77c62dbe7fedfb0a4e5ec2f91078080800ab1f18358e5f31fcc8faa023c4.sig"),
	}, {
		name: "attestation passed a tag",
		fn:   AttestationTag,
		ref:  name.MustParseReference("gcr.io/distroless/static:nonroot"),
		want: name.MustParseReference("gcr.io/distroless/static:sha256-be5d77c62dbe7fedfb0a4e5ec2f91078080800ab1f18358e5f31fcc8faa023c4.att"),
	}, {
		name: "attestation passed a tag (w/ custom suffix)",
		fn:   AttestationTag,
		ref:  name.MustParseReference("gcr.io/distroless/static:nonroot"),
		opts: []Option{WithAttestationSuffix("snowflake")},
		want: name.MustParseReference("gcr.io/distroless/static:sha256-be5d77c62dbe7fedfb0a4e5ec2f91078080800ab1f18358e5f31fcc8faa023c4.snowflake"),
	}, {
		name: "attestation passed a digest",
		fn:   AttestationTag,
		ref:  name.MustParseReference("gcr.io/distroless/static@sha256:be5d77c62dbe7fedfb0a4e5ec2f91078080800ab1f18358e5f31fcc8faa023c4"),
		want: name.MustParseReference("gcr.io/distroless/static:sha256-be5d77c62dbe7fedfb0a4e5ec2f91078080800ab1f18358e5f31fcc8faa023c4.att"),
	}, {
		name: "sbom passed a tag",
		fn:   SBOMTag,
		ref:  name.MustParseReference("gcr.io/distroless/static:nonroot"),
		want: name.MustParseReference("gcr.io/distroless/static:sha256-be5d77c62dbe7fedfb0a4e5ec2f91078080800ab1f18358e5f31fcc8faa023c4.sbom"),
	}, {
		name: "sbom passed a tag (w/ custom suffix)",
		fn:   SBOMTag,
		ref:  name.MustParseReference("gcr.io/distroless/static:nonroot"),
		opts: []Option{WithSBOMSuffix("snowflake")},
		want: name.MustParseReference("gcr.io/distroless/static:sha256-be5d77c62dbe7fedfb0a4e5ec2f91078080800ab1f18358e5f31fcc8faa023c4.snowflake"),
	}, {
		name: "sbom passed a digest",
		fn:   SBOMTag,
		ref:  name.MustParseReference("gcr.io/distroless/static@sha256:be5d77c62dbe7fedfb0a4e5ec2f91078080800ab1f18358e5f31fcc8faa023c4"),
		want: name.MustParseReference("gcr.io/distroless/static:sha256-be5d77c62dbe7fedfb0a4e5ec2f91078080800ab1f18358e5f31fcc8faa023c4.sbom"),
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := test.fn(test.ref, test.opts...)
			if err != nil {
				t.Fatalf("fn() = %v", err)
			}
			if got.String() != test.want.String() {
				t.Errorf("fn() = %s, wanted %s", got.String(), test.want.String())
			}
		})
	}
}

func TestTagMethodErrors(t *testing.T) {
	rg := remoteGet
	defer func() {
		remoteGet = rg
	}()
	errRemoteGet := errors.New("remote.Get failure")
	remoteGet = func(_ name.Reference, _ ...remote.Option) (*remote.Descriptor, error) {
		return nil, errRemoteGet
	}

	tests := []struct {
		name string
		fn   func(name.Reference, ...Option) (name.Tag, error)
		ref  name.Reference
		want error
	}{
		{
			name: "signature passed a tag",
			fn:   SignatureTag,
			ref:  name.MustParseReference("gcr.io/distroless/static:nonroot"),
			want: errRemoteGet,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tag, got := test.fn(test.ref)
			if got == nil {
				t.Fatalf("fn() = %v, wanted %v", tag, test.want)
			}
			if got.Error() != test.want.Error() {
				t.Errorf("fn() = %v, wanted %v", got, test.want)
			}
		})
	}
}

func TestDockercontentDigest(t *testing.T) {
	rg := remoteGet
	defer func() {
		remoteGet = rg
	}()
	remoteGet = func(_ name.Reference, _ ...remote.Option) (*remote.Descriptor, error) {
		return &remote.Descriptor{
			Descriptor: v1.Descriptor{
				Digest: v1.Hash{
					Algorithm: "sha256",
					// As of 2021-09-20:
					// crane digest gcr.io/distroless/static:nonroot
					Hex: "be5d77c62dbe7fedfb0a4e5ec2f91078080800ab1f18358e5f31fcc8faa023c4",
				},
			},
		}, nil
	}

	repo, err := name.NewRepository("gcr.io/distroless/static")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tests := []struct {
		name    string
		tag     name.Tag
		wantTag name.Tag
	}{
		{
			name:    "docker content digest for tag",
			tag:     name.MustParseReference("gcr.io/distroless/static:sha256-be5d77c62dbe7fedfb0a4e5ec2f91078080800ab1f18358e5f31fcc8faa023c4.sig").(name.Tag),
			wantTag: repo.Tag("sha256:be5d77c62dbe7fedfb0a4e5ec2f91078080800ab1f18358e5f31fcc8faa023c4"),
		},
		{
			name:    "docker content digest for attestation",
			tag:     name.MustParseReference("gcr.io/distroless/static:sha256-be5d77c62dbe7fedfb0a4e5ec2f91078080800ab1f18358e5f31fcc8faa023c4.att").(name.Tag),
			wantTag: repo.Tag("sha256:be5d77c62dbe7fedfb0a4e5ec2f91078080800ab1f18358e5f31fcc8faa023c4"),
		},
		{
			name:    "docker content digest for SBOM",
			tag:     name.MustParseReference("gcr.io/distroless/static:sha256-be5d77c62dbe7fedfb0a4e5ec2f91078080800ab1f18358e5f31fcc8faa023c4.sbom").(name.Tag),
			wantTag: repo.Tag("sha256:be5d77c62dbe7fedfb0a4e5ec2f91078080800ab1f18358e5f31fcc8faa023c4"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotTag, err := DockerContentDigest(test.tag)
			if err != nil {
				t.Fatalf("fn() = %v", err)
			}
			if gotTag != test.wantTag {
				t.Errorf("fn() = %s, wanted %s", gotTag.String(), test.wantTag.String())
			}
		})
	}
}

func TestPayload(t *testing.T) {
	tests := []struct {
		name      string
		size      int64
		env       map[string]string
		wantError error
	}{
		{
			name:      "within default limit",
			size:      1000,
			wantError: nil,
		},
		{
			name:      "excceds default limit",
			size:      1073741824,
			wantError: errors.New("size of layer (1073741824) exceeded the limit (134217728)"),
		},
		{
			name:      "exceeds overridden limit",
			size:      5120,
			env:       map[string]string{"COSIGN_MAX_ATTACHMENT_SIZE": "1KB"},
			wantError: errors.New("size of layer (5120) exceeded the limit (1000)"),
		},
		{
			name: "within overridden limit",
			size: 5120,
			env:  map[string]string{"COSIGN_MAX_ATTACHMENT_SIZE": "10KB"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for k, v := range test.env {
				t.Setenv(k, v)
			}
			a := attached{
				layer: &mockLayer{
					size: test.size,
				},
			}
			_, err := a.Payload()
			if test.wantError != nil && test.wantError.Error() != err.Error() {
				t.Fatalf("Payload() = %v, wanted %v", err, test.wantError)
			}
			if test.wantError == nil && err != nil {
				t.Fatalf("Payload() = %v, wanted %v", err, test.wantError)
			}
		})
	}
}

type mockLayer struct {
	size int64
}

func (m *mockLayer) Compressed() (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("test payload")), nil
}

func (m *mockLayer) Size() (int64, error) {
	return m.size, nil
}

func (m *mockLayer) Digest() (v1.Hash, error)             { panic("not implemented") }
func (m *mockLayer) DiffID() (v1.Hash, error)             { panic("not implemented") }
func (m *mockLayer) Uncompressed() (io.ReadCloser, error) { panic("not implemented") }
func (m *mockLayer) MediaType() (types.MediaType, error)  { panic("not implemented") }
