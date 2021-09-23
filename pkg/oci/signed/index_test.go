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

package signed

import (
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/cosign/pkg/oci"
)

func TestImageIndex(t *testing.T) {
	ii, err := random.Index(300 /* bytes */, 5 /* layers */, 3 /* images */)
	if err != nil {
		t.Fatalf("random.Image() = %v", err)
	}

	ni, err := random.Index(300 /* bytes */, 5 /* layers */, 3 /* images */)
	if err != nil {
		t.Fatalf("random.Image() = %v", err)
	}
	ni = mutate.AppendManifests(ni, mutate.IndexAddendum{
		Add: ii,
	})

	im, err := ni.IndexManifest()
	if err != nil {
		t.Fatalf("IndexManifest() = %v", err)
	}

	sii := ImageIndex(ni)

	sel := make([]oci.SignedEntity, 0, len(im.Manifests)+1)
	sel = append(sel, sii)

	for _, desc := range im.Manifests {
		switch desc.MediaType {
		case types.OCIImageIndex, types.DockerManifestList:
			se, err := sii.SignedImageIndex(desc.Digest)
			if err != nil {
				t.Fatalf("SignedImageIndex() = %v", err)
			}
			sel = append(sel, se)
		case types.OCIManifestSchema1, types.DockerManifestSchema2:
			se, err := sii.SignedImage(desc.Digest)
			if err != nil {
				t.Fatalf("SignedImage() = %v", err)
			}
			sel = append(sel, se)
		default:
			t.Errorf("Unsupported media type: %v", desc.MediaType)
		}
	}

	if se, err := sii.SignedImageIndex(v1.Hash{}); err == nil {
		t.Errorf("SignedImageIndex() = %#v, wanted error", se)
	}
	if se, err := sii.SignedImage(v1.Hash{}); err == nil {
		t.Errorf("SignedImage() = %#v, wanted error", se)
	}

	for _, se := range sel {
		sigs, err := se.Signatures()
		if err != nil {
			t.Fatalf("Signatures() = %v", err)
		}

		if sl, err := sigs.Get(); err != nil {
			t.Errorf("Get() = %v", err)
		} else if got, want := len(sl), 0; got != want {
			t.Errorf("len(Get()) = %d, wanted %d", got, want)
		}
	}
}
