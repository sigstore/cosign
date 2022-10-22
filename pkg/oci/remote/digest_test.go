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

package remote

import (
	"errors"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

func TestResolveDigest(t *testing.T) {
	rg := remoteGet
	defer func() {
		remoteGet = rg
	}()

	tag := name.MustParseReference("gcr.io/distroless/static:nonroot")
	// As of 2021-09-20:
	// crane digest gcr.io/distroless/static:nonroot
	digest := name.MustParseReference("gcr.io/distroless/static@sha256:be5d77c62dbe7fedfb0a4e5ec2f91078080800ab1f18358e5f31fcc8faa023c4")

	t.Run("digest doesn't call remote.Get", func(t *testing.T) {
		remoteGet = func(ref name.Reference, options ...remote.Option) (*remote.Descriptor, error) {
			t.Fatal("ResolveDigest should not call remote.Get.")
			return nil, nil
		}

		got, err := ResolveDigest(digest)
		if err != nil {
			t.Fatalf("ResolveDigest() = %v", err)
		}
		if want := digest; got != want {
			t.Errorf("ResolveDigest() = %v, wanted %v", got, want)
		}
	})

	t.Run("tag calls remote.Get", func(t *testing.T) {
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

		got, err := ResolveDigest(tag)
		if err != nil {
			t.Fatalf("ResolveDigest() = %v", err)
		}
		if want := digest; got != want {
			t.Errorf("ResolveDigest() = %v, wanted %v", got, want)
		}
	})

	t.Run("remote.Get errors propagate", func(t *testing.T) {
		want := errors.New("we should propagate this error")
		remoteGet = func(ref name.Reference, options ...remote.Option) (*remote.Descriptor, error) {
			return nil, want
		}

		_, got := ResolveDigest(tag)
		if !errors.Is(got, want) {
			t.Fatalf("ResolveDigest() = %v, wanted %v", got, want)
		}
	})
}
