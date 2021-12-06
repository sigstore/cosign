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

package layout

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/cosign/pkg/oci/mutate"
	"github.com/sigstore/cosign/pkg/oci/signed"
	"github.com/sigstore/cosign/pkg/oci/static"
)

func TestReadWrite(t *testing.T) {
	// write random signed image to disk
	si := randomSignedImage(t)
	tmp := t.TempDir()
	if err := WriteSignedImage(tmp, si); err != nil {
		t.Fatal(err)
	}

	// read the image and make sure the signatures exist
	imageIndex, err := SignedImageIndex(tmp)
	if err != nil {
		t.Fatal(err)
	}
	gotSignedImage, err := imageIndex.SignedImage(v1.Hash{})
	if err != nil {
		t.Fatal(err)
	}
	// compare the image we read with the one we wrote
	compareDigests(t, si, gotSignedImage)

	// make sure we have 5 attestations
	attImg, err := imageIndex.Attestations()
	if err != nil {
		t.Fatal(err)
	}
	atts, err := attImg.Get()
	if err != nil {
		t.Fatal(err)
	}
	if len(atts) != 5 {
		t.Fatal("expected 5 attestations")
	}

	// make sure signatures are correct
	sigImage, err := imageIndex.Signatures()
	if err != nil {
		t.Fatal(err)
	}
	sigs, err := sigImage.Get()
	if err != nil {
		t.Fatal(err)
	}
	want := 6
	if len(sigs) != want {
		t.Fatal("didn't get the expected number of signatures")
	}
	// make sure the annotation is correct
	for i, sig := range sigs {
		annotations, err := sig.Annotations()
		if err != nil {
			t.Fatal(err)
		}
		val, ok := annotations["layer"]
		if !ok {
			t.Fatal("expected annotation doesn't exist on signature")
		}
		if val != fmt.Sprintf("%d", i) {
			t.Fatal("expected annotation isn't correct")
		}
	}
}

func randomSignedImage(t *testing.T) oci.SignedImage {
	i, err := random.Image(300 /* byteSize */, 7 /* layers */)
	if err != nil {
		t.Fatalf("random.Image() = %v", err)
	}
	si := signed.Image(i)

	want := 6 // Add 6 signatures
	for i := 0; i < want; i++ {
		annotationOption := static.WithAnnotations(map[string]string{"layer": fmt.Sprintf("%d", i)})
		sig, err := static.NewSignature(nil, fmt.Sprintf("%d", i), annotationOption)
		if err != nil {
			t.Fatalf("static.NewSignature() = %v", err)
		}
		si, err = mutate.AttachSignatureToImage(si, sig)
		if err != nil {
			t.Fatalf("SignEntity() = %v", err)
		}
	}

	want = 5 // Add 5 attestations
	for i := 0; i < want; i++ {
		sig, err := static.NewAttestation([]byte(fmt.Sprintf("%d", i)))
		if err != nil {
			t.Fatalf("static.NewSignature() = %v", err)
		}
		si, err = mutate.AttachAttestationToImage(si, sig)
		if err != nil {
			t.Fatalf("SignEntity() = %v", err)
		}
	}

	return si
}

func compareDigests(t *testing.T, img1 oci.SignedImage, img2 oci.SignedImage) {
	d1, err := img1.Digest()
	if err != nil {
		t.Fatal(err)
	}
	d2, err := img2.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if d := cmp.Diff(d1, d2); d != "" {
		t.Fatalf("digests are different: %s", d)
	}
}
