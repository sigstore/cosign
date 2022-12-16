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
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/cosign/v2/pkg/oci"
)

func TestSignedImageIndex(t *testing.T) {
	ri := remote.Image
	rix := remote.Index
	t.Cleanup(func() {
		remoteImage = ri
		remoteIndex = rix
	})
	wantLayers := int64(7)
	wantImages := int64(1)

	l1, err := random.Image(300 /* byteSize */, wantLayers)
	if err != nil {
		t.Fatalf("random.Index() = %v", err)
	}
	l2, err := random.Index(300 /* byteSize */, wantLayers, wantImages)
	if err != nil {
		t.Fatalf("random.Index() = %v", err)
	}
	l3 := mutate.AppendManifests(
		empty.Index,
		mutate.IndexAddendum{
			Add: l2,
		},
		mutate.IndexAddendum{
			Add: l1,
		},
	)

	remoteImage = func(ref name.Reference, options ...remote.Option) (v1.Image, error) {
		// Only called for signature images
		return random.Image(300 /* byteSize */, wantLayers)
	}
	remoteIndex = func(ref name.Reference, options ...remote.Option) (ii v1.ImageIndex, err error) {
		return l3, nil
	}

	ref, err := name.ParseReference("gcr.io/distroless/static:nonroot")
	if err != nil {
		t.Fatalf("ParseRef() = %v", err)
	}

	sii, err := SignedImageIndex(ref)
	if err != nil {
		t.Fatalf("Signatures() = %v", err)
	}

	sigs, err := sii.Signatures()
	if err != nil {
		t.Fatalf("Signatures() = %v", err)
	}

	if sl, err := sigs.Get(); err != nil {
		t.Errorf("Get() = %v", err)
	} else if got := int64(len(sl)); got != wantLayers {
		t.Errorf("len(Get()) = %d, wanted %d", got, wantLayers)
	}

	imf, err := sii.IndexManifest()
	if err != nil {
		t.Fatalf("IndexManifest() = %v", err)
	}

	for _, desc := range imf.Manifests {
		var se oci.SignedEntity
		switch desc.MediaType {
		case types.OCIImageIndex, types.DockerManifestList:
			se, err = sii.SignedImageIndex(desc.Digest)
			if err != nil {
				t.Fatalf("SignedImage() = %v", err)
			}

		case types.OCIManifestSchema1, types.DockerManifestSchema2:
			se, err = sii.SignedImage(desc.Digest)
			if err != nil {
				t.Fatalf("SignedImage() = %v", err)
			}
		default:
			t.Fatalf("unknown mime type: %v", desc.MediaType)
		}

		sigs, err := se.Signatures()
		if err != nil {
			t.Fatalf("Signatures() = %v", err)
		}

		if sl, err := sigs.Get(); err != nil {
			t.Errorf("Get() = %v", err)
		} else if got := int64(len(sl)); got != wantLayers {
			t.Errorf("len(Get()) = %d, wanted %d", got, wantLayers)
		}

		atts, err := se.Attestations()
		if err != nil {
			t.Fatalf("Signatures() = %v", err)
		}

		if al, err := atts.Get(); err != nil {
			t.Errorf("Get() = %v", err)
		} else if got := int64(len(al)); got != wantLayers {
			t.Errorf("len(Get()) = %d, wanted %d", got, wantLayers)
		}
	}
}
