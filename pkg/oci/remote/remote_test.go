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
	"encoding/base64"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/pkg/errors"
)

func must(img v1.Image, err error) v1.Image {
	if err != nil {
		panic(err.Error())
	}
	return img
}

func mustDecode(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err.Error())
	}
	return b
}

func TestTagMethods(t *testing.T) {
	rg := remoteGet
	defer func() {
		remoteGet = rg
	}()
	remoteGet = func(ref name.Reference, options ...remote.Option) (*remote.Descriptor, error) {
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
	remoteGet = func(ref name.Reference, options ...remote.Option) (*remote.Descriptor, error) {
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
