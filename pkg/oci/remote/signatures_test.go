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
	"net/http"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

func TestSignaturesErrors(t *testing.T) {
	ri := remote.Image
	t.Cleanup(func() {
		remoteImage = ri
	})

	t.Run("404 returns empty", func(t *testing.T) {
		remoteImage = func(ref name.Reference, options ...remote.Option) (v1.Image, error) {
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
		remoteImage = func(ref name.Reference, options ...remote.Option) (v1.Image, error) {
			return nil, want
		}

		_, err := Signatures(name.MustParseReference("gcr.io/distroless/static:sha256-deadbeef.sig"))
		if !errors.Is(err, want) {
			t.Fatalf("Signatures() = %v, wanted %v", err, want)
		}
	})

	t.Run("other errors propagate", func(t *testing.T) {
		want := errors.New("it's my error, I can cry if I want to")
		remoteImage = func(ref name.Reference, options ...remote.Option) (v1.Image, error) {
			return nil, want
		}

		_, err := Signatures(name.MustParseReference("gcr.io/distroless/static:sha256-deadbeef.sig"))
		if !errors.Is(err, want) {
			t.Fatalf("Signatures() = %v, wanted %v", err, want)
		}
	})
}
