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
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

func TestSignedImage(t *testing.T) {
	ri := remote.Image
	t.Cleanup(func() {
		remoteImage = ri
	})
	wantLayers := int64(7)

	remoteImage = func(ref name.Reference, options ...remote.Option) (v1.Image, error) {
		// Only called for signature images
		return random.Image(300 /* byteSize */, wantLayers)
	}

	ref, err := name.ParseReference("gcr.io/distroless/static:nonroot")
	if err != nil {
		t.Fatalf("ParseRef() = %v", err)
	}

	si, err := SignedImage(ref)
	if err != nil {
		t.Fatalf("Signatures() = %v", err)
	}

	sigs, err := si.Signatures()
	if err != nil {
		t.Fatalf("Signatures() = %v", err)
	}

	if sl, err := sigs.Get(); err != nil {
		t.Errorf("Get() = %v", err)
	} else if got := int64(len(sl)); got != wantLayers {
		t.Errorf("len(Get()) = %d, wanted %d", got, wantLayers)
	}

	atts, err := si.Attestations()
	if err != nil {
		t.Fatalf("Signatures() = %v", err)
	}

	if al, err := atts.Get(); err != nil {
		t.Errorf("Get() = %v", err)
	} else if got := int64(len(al)); got != wantLayers {
		t.Errorf("len(Get()) = %d, wanted %d", got, wantLayers)
	}
}

func TestSignedImageWithAttachment(t *testing.T) {
	ri := remote.Image
	t.Cleanup(func() {
		remoteImage = ri
	})
	wantLayers := int64(1) // File must have a single layer

	remoteImage = func(ref name.Reference, options ...remote.Option) (v1.Image, error) {
		// Only called for signature images
		return random.Image(300 /* byteSize */, wantLayers)
	}

	ref, err := name.ParseReference("gcr.io/distroless/static:nonroot")
	if err != nil {
		t.Fatalf("ParseRef() = %v", err)
	}

	si, err := SignedImage(ref)
	if err != nil {
		t.Fatalf("Signatures() = %v", err)
	}

	file, err := si.Attachment("sbom")
	if err != nil {
		t.Fatalf("Signatures() = %v", err)
	}

	payload, err := file.Payload()
	if err != nil {
		t.Errorf("Payload() = %v", err)
	}
	// We check greater than because it's wrapped in a tarball with `random.Layer`
	if len(payload) < 300 {
		t.Errorf("Payload() = %d bytes, wanted %d", len(payload), 300)
	}
}
