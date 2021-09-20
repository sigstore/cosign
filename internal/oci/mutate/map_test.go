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

package mutate

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/cosign/internal/oci"
	"github.com/sigstore/cosign/internal/oci/signed"
)

func TestMapImage(t *testing.T) {
	i, err := random.Image(300 /* bytes */, 3 /* layers */)
	if err != nil {
		t.Fatalf("random.Image() = %v", err)
	}
	si := signed.Image(i)

	t.Run("one call to identity mutator", func(t *testing.T) {
		calls := 0
		rsi, err := Map(context.Background(), si, func(c context.Context, se oci.SignedEntity) (oci.SignedEntity, error) {
			calls++
			return se, nil
		})
		if err != nil {
			t.Fatalf("Map() = %v", err)
		}
		if rsi != si {
			t.Fatalf("Map() = %#v, wanted %#v", rsi, si)
		}
		if calls != 1 {
			t.Fatalf("Map called %d times, wanted 1", calls)
		}
	})

	t.Run("error propagates", func(t *testing.T) {
		want := errors.New("this is the error I expect")
		_, got := Map(context.Background(), si, func(c context.Context, se oci.SignedEntity) (oci.SignedEntity, error) {
			return nil, want
		})
		if !errors.Is(got, want) {
			t.Fatalf("Map() = %v, wanted %v", got, want)
		}
	})

	t.Run("new result image", func(t *testing.T) {
		i, err := random.Image(300 /* bytes */, 3 /* layers */)
		if err != nil {
			t.Fatalf("random.Image() = %v", err)
		}
		want := signed.Image(i)

		got, err := Map(context.Background(), si, func(c context.Context, se oci.SignedEntity) (oci.SignedEntity, error) {
			return want, nil
		})
		if err != nil {
			t.Fatalf("Map() = %v", err)
		}
		if got != want {
			t.Fatalf("Map() = %#v, wanted %#v", got, want)
		}
	})

	t.Run("filtered image", func(t *testing.T) {
		got, err := Map(context.Background(), si, func(c context.Context, se oci.SignedEntity) (oci.SignedEntity, error) {
			return nil, nil
		})
		if err != nil {
			t.Fatalf("Map() = %v", err)
		}
		if got != nil {
			t.Fatalf("Map() = %#v, wanted nil", got)
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
		after := 0
		rsi, err := Map(context.Background(), sii, func(ctx context.Context, se oci.SignedEntity) (oci.SignedEntity, error) {
			calls++
			if IsAfterChildren(ctx) {
				after++
			}
			return se, nil
		})
		if err != nil {
			t.Fatalf("Map() = %v", err)
		}
		if rsi != sii {
			t.Fatalf("Map() = %#v, wanted %#v", rsi, sii)
		}
		if calls != 6 {
			t.Fatalf("Map called %d times, wanted 6", calls)
		}
		if after != 0 {
			t.Fatalf("Map called %d times (w/ after), wanted 0", after)
		}
	})

	t.Run("just one call to root index w/ ErrSkipChildren", func(t *testing.T) {
		calls := 0
		_, err := Map(context.Background(), sii, func(ctx context.Context, se oci.SignedEntity) (oci.SignedEntity, error) {
			calls++
			if se != sii {
				t.Errorf("Wanted mutator called on %#v, got call on %#v", sii, se)
			}
			return se, ErrSkipChildren
		})
		if err != nil {
			t.Fatalf("Map() = %v", err)
		}
		if calls != 1 {
			t.Fatalf("Map called %d times, wanted 1", calls)
		}
	})

	t.Run("two calls to mutator with IsAfterChildren", func(t *testing.T) {
		before := 0
		after := 0
		rsi, err := Map(context.Background(), sii, func(ctx context.Context, se oci.SignedEntity) (oci.SignedEntity, error) {
			if IsBeforeChildren(ctx) {
				before++
			}
			if IsAfterChildren(ctx) {
				after++
			}
			if sii, ok := se.(oci.SignedImageIndex); ok {
				return sii, nil
			}
			i, err := random.Image(300 /* bytes */, 3 /* layers */)
			if err != nil {
				t.Fatalf("random.Image() = %v", err)
			}
			return signed.Image(i), nil
		})
		if err != nil {
			t.Fatalf("Map() = %v", err)
		}
		if rsi == sii {
			t.Fatalf("Map() = %#v, wanted something new!", rsi)
		}
		if before != 2 {
			t.Fatalf("Map called %d times (w/ before), wanted 2", before)
		}
		if after != 2 {
			t.Fatalf("Map called %d times (w/ after), wanted 2", after)
		}
	})

	t.Run("test filtering images", func(t *testing.T) {
		rsi, err := Map(context.Background(), sii, func(ctx context.Context, se oci.SignedEntity) (oci.SignedEntity, error) {
			if _, ok := se.(oci.SignedImage); ok {
				return nil, nil
			}
			return se, nil
		})
		if err != nil {
			t.Fatalf("Map() = %v", err)
		}
		if rsi == sii {
			t.Fatalf("Map() = %#v, wanted something new!", rsi)
		}
		// Make sure no images remain!
		im, err := rsi.(oci.SignedImageIndex).IndexManifest()
		if err != nil {
			t.Fatalf("IndexManifest() = %v", err)
		}
		for _, desc := range im.Manifests {
			if desc.MediaType == types.DockerManifestSchema2 {
				t.Error("Found an image media type!")
			}
		}
	})

	t.Run("test filtering indices", func(t *testing.T) {
		rsi, err := Map(context.Background(), sii, func(ctx context.Context, se oci.SignedEntity) (oci.SignedEntity, error) {
			if IsBeforeChildren(ctx) && se != sii {
				return nil, nil
			}
			return se, nil
		})
		if err != nil {
			t.Fatalf("Map() = %v", err)
		}
		if rsi == sii {
			t.Fatalf("Map() = %#v, wanted something new!", rsi)
		}
		// Make sure no indices remain!
		im, err := rsi.(oci.SignedImageIndex).IndexManifest()
		if err != nil {
			t.Fatalf("IndexManifest() = %v", err)
		}
		for _, desc := range im.Manifests {
			if desc.MediaType != types.DockerManifestSchema2 {
				t.Errorf("MediaType = %s, wanted %s", desc.MediaType, types.DockerManifestSchema2)
			}
		}
	})

	t.Run("error propagates from child image", func(t *testing.T) {
		want := errors.New("this is the error I expect")
		_, got := Map(context.Background(), sii, func(c context.Context, se oci.SignedEntity) (oci.SignedEntity, error) {
			if _, ok := se.(oci.SignedImage); !ok {
				return se, nil
			}
			return nil, want
		})
		if !errors.Is(got, want) {
			t.Fatalf("Map() = %v, wanted %v", got, want)
		}
	})

	t.Run("error propagates from child index", func(t *testing.T) {
		want := errors.New("this is the error I expect")
		_, got := Map(context.Background(), sii, func(ctx context.Context, se oci.SignedEntity) (oci.SignedEntity, error) {
			if IsBeforeChildren(ctx) && se != sii {
				return nil, want
			}
			return se, nil
		})
		if !errors.Is(got, want) {
			t.Fatalf("Map() = %v, wanted %v", got, want)
		}
	})
}
