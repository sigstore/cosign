//
// Copyright 2023 The Sigstore Authors.
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
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

type fakeImageIndex struct {
	manifest *v1.IndexManifest
	err      error
}

func (fii *fakeImageIndex) MediaType() (types.MediaType, error)       { return types.OCIImageIndex, nil }
func (fii *fakeImageIndex) Digest() (v1.Hash, error)                  { return v1.Hash{}, errors.New("unimplemented") }
func (fii *fakeImageIndex) Size() (int64, error)                      { return 0, errors.New("unimplemented") }
func (fii *fakeImageIndex) IndexManifest() (*v1.IndexManifest, error) { return fii.manifest, fii.err }
func (fii *fakeImageIndex) RawManifest() ([]byte, error)              { return nil, errors.New("unimplemented") }
func (fii *fakeImageIndex) Image(v1.Hash) (v1.Image, error)           { return nil, errors.New("unimplemented") }
func (fii *fakeImageIndex) ImageIndex(v1.Hash) (v1.ImageIndex, error) {
	return nil, errors.New("unimplemented")
}

func TestReferrersSortsManifestsByDigest(t *testing.T) {
	orig := remoteReferrers
	t.Cleanup(func() { remoteReferrers = orig })

	a := v1.Descriptor{Digest: v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("a", 64)}}
	b := v1.Descriptor{Digest: v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("b", 64)}}
	c := v1.Descriptor{Digest: v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("c", 64)}}

	remoteReferrers = func(_ name.Digest, _ ...remote.Option) (v1.ImageIndex, error) {
		return &fakeImageIndex{
			manifest: &v1.IndexManifest{Manifests: []v1.Descriptor{b, c, a}},
		}, nil
	}

	d, err := name.NewDigest("example.com/repo@sha256:" + strings.Repeat("0", 64))
	if err != nil {
		t.Fatalf("name.NewDigest() = %v", err)
	}

	got, err := Referrers(d, "sig")
	if err != nil {
		t.Fatalf("Referrers() = %v", err)
	}
	if len(got.Manifests) != 3 {
		t.Fatalf("got %d manifests, want 3", len(got.Manifests))
	}
	if got.Manifests[0].Digest.String() != a.Digest.String() ||
		got.Manifests[1].Digest.String() != b.Digest.String() ||
		got.Manifests[2].Digest.String() != c.Digest.String() {
		t.Fatalf("unexpected order: got %v", []string{got.Manifests[0].Digest.String(), got.Manifests[1].Digest.String(), got.Manifests[2].Digest.String()})
	}
}

func TestReferrersAllowsEmptyArtifactType(t *testing.T) {
	orig := remoteReferrers
	t.Cleanup(func() { remoteReferrers = orig })

	a := v1.Descriptor{Digest: v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("a", 64)}}
	b := v1.Descriptor{Digest: v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("b", 64)}}

	remoteReferrers = func(_ name.Digest, _ ...remote.Option) (v1.ImageIndex, error) {
		return &fakeImageIndex{
			manifest: &v1.IndexManifest{Manifests: []v1.Descriptor{b, a}},
		}, nil
	}

	d, err := name.NewDigest("example.com/repo@sha256:" + strings.Repeat("0", 64))
	if err != nil {
		t.Fatalf("name.NewDigest() = %v", err)
	}

	got, err := Referrers(d, "")
	if err != nil {
		t.Fatalf("Referrers() = %v", err)
	}
	if len(got.Manifests) != 2 {
		t.Fatalf("got %d manifests, want 2", len(got.Manifests))
	}
	if got.Manifests[0].Digest.String() != a.Digest.String() || got.Manifests[1].Digest.String() != b.Digest.String() {
		t.Fatalf("unexpected order: got %v", []string{got.Manifests[0].Digest.String(), got.Manifests[1].Digest.String()})
	}
}

func TestReferrersPropagatesReferrersError(t *testing.T) {
	orig := remoteReferrers
	t.Cleanup(func() { remoteReferrers = orig })

	remoteReferrers = func(_ name.Digest, _ ...remote.Option) (v1.ImageIndex, error) {
		return nil, errors.New("boom")
	}

	d, err := name.NewDigest("example.com/repo@sha256:" + strings.Repeat("0", 64))
	if err != nil {
		t.Fatalf("name.NewDigest() = %v", err)
	}

	if _, err := Referrers(d, "sig"); err == nil {
		t.Fatalf("expected error, got nil")
	}
}

func TestReferrersPropagatesIndexManifestError(t *testing.T) {
	orig := remoteReferrers
	t.Cleanup(func() { remoteReferrers = orig })

	remoteReferrers = func(_ name.Digest, _ ...remote.Option) (v1.ImageIndex, error) {
		return &fakeImageIndex{
			err: errors.New("indexmanifest error"),
		}, nil
	}

	d, err := name.NewDigest("example.com/repo@sha256:" + strings.Repeat("0", 64))
	if err != nil {
		t.Fatalf("name.NewDigest() = %v", err)
	}

	if _, err := Referrers(d, "sig"); err == nil {
		t.Fatalf("expected error, got nil")
	}
}
