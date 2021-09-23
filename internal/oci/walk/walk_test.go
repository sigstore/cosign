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

package walk

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/sigstore/cosign/internal/oci"
	"github.com/sigstore/cosign/internal/oci/signed"
)

func TestMapImage(t *testing.T) {
	i, err := random.Image(300 /* bytes */, 3 /* layers */)
	if err != nil {
		t.Fatalf("random.Image() = %v", err)
	}
	si := signed.Image(i)

	t.Run("walk image, no errors", func(t *testing.T) {
		calls := 0
		err := SignedEntity(context.Background(), si, func(c context.Context, se oci.SignedEntity) error {
			calls++
			return nil
		})
		if err != nil {
			t.Fatalf("Map() = %v", err)
		}
		if calls != 1 {
			t.Fatalf("Map called %d times, wanted 1", calls)
		}
	})

	t.Run("error propagates", func(t *testing.T) {
		want := errors.New("this is the error I expect")
		got := SignedEntity(context.Background(), si, func(c context.Context, se oci.SignedEntity) error {
			return want
		})
		if !errors.Is(got, want) {
			t.Fatalf("Map() = %v, wanted %v", got, want)
		}
	})
}

func TestMapImageIndex(t *testing.T) {
	ii, err := random.Index(300 /* bytes */, 3 /* layers */, 2 /* images */)
	if err != nil {
		t.Fatalf("random.Image() = %v", err)
	}
	ii2, err := random.Index(300 /* bytes */, 3 /* layers */, 2 /* images */)
	if err != nil {
		t.Fatalf("random.Image() = %v", err)
	}
	sii := signed.ImageIndex(mutate.AppendManifests(ii, mutate.IndexAddendum{
		Add: ii2,
	}))

	t.Run("six calls to identity mutator", func(t *testing.T) {
		calls := 0
		err := SignedEntity(context.Background(), sii, func(ctx context.Context, se oci.SignedEntity) error {
			calls++
			return nil
		})
		if err != nil {
			t.Fatalf("Map() = %v", err)
		}
		if calls != 6 {
			t.Fatalf("Map called %d times, wanted 6", calls)
		}
	})
}
