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
	"bytes"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/fake"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

func TestSignaturesErrors(t *testing.T) {
	ri := remote.Image
	t.Cleanup(func() {
		remoteImage = ri
	})

	t.Run("404 returns empty", func(t *testing.T) {
		remoteImage = func(_ name.Reference, _ ...remote.Option) (v1.Image, error) {
			return nil, &transport.Error{
				StatusCode: http.StatusNotFound,
			}
		}

		sigs, err := Signatures(name.MustParseReference("gcr.io/distroless/static:sha256-deadbeef.sig"))
		if err != nil {
			t.Fatalf("Signatures() = %v", err)
		}
		if sl, err := sigs.Get(); err != nil {
			t.Fatalf("Get() = %v", err)
		} else if len(sl) != 0 {
			t.Fatalf("len(Get()) = %d, wanted 0", len(sl))
		}
	})

	t.Run("other transport errors propagate", func(t *testing.T) {
		want := &transport.Error{
			StatusCode: http.StatusInternalServerError,
		}
		remoteImage = func(_ name.Reference, _ ...remote.Option) (v1.Image, error) {
			return nil, want
		}

		_, err := Signatures(name.MustParseReference("gcr.io/distroless/static:sha256-deadbeef.sig"))
		if !errors.Is(err, want) {
			t.Fatalf("Signatures() = %v, wanted %v", err, want)
		}
	})

	t.Run("other errors propagate", func(t *testing.T) {
		want := errors.New("it's my error, I can cry if I want to")
		remoteImage = func(_ name.Reference, _ ...remote.Option) (v1.Image, error) {
			return nil, want
		}

		_, err := Signatures(name.MustParseReference("gcr.io/distroless/static:sha256-deadbeef.sig"))
		if !errors.Is(err, want) {
			t.Fatalf("Signatures() = %v, wanted %v", err, want)
		}
	})

	t.Run("too many layers", func(t *testing.T) {
		remoteImage = func(_ name.Reference, _ ...remote.Option) (v1.Image, error) {
			return &fake.FakeImage{
				ManifestStub: func() (*v1.Manifest, error) {
					return &v1.Manifest{
						Layers: make([]v1.Descriptor, 10000),
					}, nil
				},
			}, nil
		}
		sigs, err := Signatures(name.MustParseReference("gcr.io/distroless/static:sha256-deadbeef.sig"))
		if err != nil {
			t.Fatalf("Signatures() = %v", err)
		}
		want := errors.New("number of layers (10000) exceeded the limit (1000)")
		_, err = sigs.Get()
		if err == nil || want.Error() != err.Error() {
			t.Fatalf("Get() = %v", err)
		}
	})
}

func TestBundleLayerSizeIsBounded(t *testing.T) {
	ri := remote.Image
	t.Cleanup(func() {
		remoteImage = ri
	})

	ref := name.MustParseReference("gcr.io/distroless/static:sha256-deadbeef.bundle")

	t.Run("over limit fails before unmarshal", func(t *testing.T) {
		remoteImage = func(_ name.Reference, _ ...remote.Option) (v1.Image, error) {
			tooBig := bytes.Repeat([]byte("a"), maxBundleLayerBytes+1)
			layer := static.NewLayer(tooBig, types.MediaType("application/vnd.dev.sigstore.bundle.v0.3+json"))
			return &fake.FakeImage{
				LayersStub: func() ([]v1.Layer, error) {
					return []v1.Layer{layer}, nil
				},
			}, nil
		}

		_, err := Bundle(ref)
		if err == nil {
			t.Fatalf("Bundle() = nil, wanted error")
		}
		if want := "bundle layer exceeded max bytes"; !strings.Contains(err.Error(), want) {
			t.Fatalf("Bundle() = %v, wanted %q", err, want)
		}
	})

	t.Run("valid small bundle parses", func(t *testing.T) {
		remoteImage = func(_ name.Reference, _ ...remote.Option) (v1.Image, error) {
			ok := []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","verificationMaterial":{"publicKey":{}},"messageSignature":{"messageDigest":{"algorithm":"SHA2_256","digest":"AA=="},"signature":"AA=="}}`)
			layer := static.NewLayer(ok, types.MediaType("application/vnd.dev.sigstore.bundle.v0.3+json"))
			return &fake.FakeImage{
				LayersStub: func() ([]v1.Layer, error) {
					return []v1.Layer{layer}, nil
				},
			}, nil
		}

		b, err := Bundle(ref)
		if err != nil {
			t.Fatalf("Bundle() = %v", err)
		}
		if b == nil {
			t.Fatalf("Bundle() = nil, wanted bundle")
		}
	})
}
