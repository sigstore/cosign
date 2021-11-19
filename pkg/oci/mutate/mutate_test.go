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
	"crypto/rand"
	"errors"
	"fmt"
	"reflect"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/cosign/pkg/oci/signed"
	"github.com/sigstore/cosign/pkg/oci/static"
)

func TestAppendManifests(t *testing.T) {
	ii, err := random.Index(300 /* bytes */, 3 /* layers */, 5 /* images */)
	if err != nil {
		t.Fatalf("random.Index() = %v", err)
	}
	i2, err := random.Image(300 /* bytes */, 3 /* layers */)
	if err != nil {
		t.Fatalf("random.Image() = %v", err)
	}
	ii3, err := random.Index(300 /* bytes */, 3 /* layers */, 5 /* images */)
	if err != nil {
		t.Fatalf("random.Index() = %v", err)
	}
	ii = mutate.AppendManifests(ii, mutate.IndexAddendum{
		Add: i2,
	}, mutate.IndexAddendum{
		Add: ii3,
	})
	ii2, err := random.Index(300 /* bytes */, 3 /* layers */, 5 /* images */)
	if err != nil {
		t.Fatalf("random.Index() = %v", err)
	}
	i1, err := random.Image(300 /* bytes */, 3 /* layers */)
	if err != nil {
		t.Fatalf("random.Image() = %v", err)
	}

	tests := []struct {
		name string
		fn   func(v1.ImageIndex) v1.ImageIndex
	}{{
		name: "unsigned",
		fn: func(in v1.ImageIndex) v1.ImageIndex {
			return in
		},
	}, {
		name: "signed",
		fn: func(in v1.ImageIndex) v1.ImageIndex {
			return signed.ImageIndex(in)
		},
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ni := AppendManifests(test.fn(ii), IndexAddendum{
				Add: signed.Image(i1),
			}, IndexAddendum{
				Add: signed.ImageIndex(ii2),
			})
			if err != nil {
				t.Fatalf("AppendManifests() = %v", err)
			}

			im, err := ni.IndexManifest()
			if err != nil {
				t.Fatalf("IndexManifest() = %v", err)
			}

			if got, want := len(im.Manifests), 7+2; got != want {
				t.Errorf("len(im.Manifests) = %d, wanted %d", got, want)
			}

			if sigs, err := ni.Signatures(); err != nil {
				t.Errorf("Signatures() = %v", err)
			} else if sl, err := sigs.Get(); err != nil {
				t.Errorf("Get() = %v", err)
			} else if len(sl) != 0 {
				t.Errorf("len(Get()) = %d, wanted 0", len(sl))
			}

			if atts, err := ni.Attestations(); err != nil {
				t.Errorf("Attestations() = %v", err)
			} else if al, err := atts.Get(); err != nil {
				t.Errorf("Get() = %v", err)
			} else if len(al) != 0 {
				t.Errorf("len(Get()) = %d, wanted 0", len(al))
			}

			d1, err := i1.Digest()
			if err != nil {
				t.Fatalf("Digest() = %v", err)
			}
			if _, err := ni.SignedImage(d1); err != nil {
				t.Fatalf("SignedImage() = %v", err)
			}

			d2, err := ii2.Digest()
			if err != nil {
				t.Fatalf("Digest() = %v", err)
			}
			if _, err := ni.SignedImageIndex(d2); err != nil {
				t.Fatalf("SignedImageIndex() = %v", err)
			}

			if se, err := ni.SignedImage(d2); err == nil {
				t.Fatalf("SignedImage() = %#v, wanted error", se)
			}
			if se, err := ni.SignedImageIndex(d1); err == nil {
				t.Fatalf("SignedImageIndex() = %#v, wanted error", se)
			}

			d3, err := i2.Digest()
			if err != nil {
				t.Fatalf("Digest() = %v", err)
			}
			if _, err := ni.SignedImage(d3); err != nil {
				t.Fatalf("SignedImage() = %v", err)
			}

			d4, err := ii3.Digest()
			if err != nil {
				t.Fatalf("Digest() = %v", err)
			}
			if _, err := ni.SignedImageIndex(d4); err != nil {
				t.Fatalf("SignedImageIndex() = %v", err)
			}
		})
	}
}

func TestSignEntity(t *testing.T) {
	i, err := random.Image(300 /* bytes */, 3 /* layers */)
	if err != nil {
		t.Fatalf("random.Image() = %v", err)
	}
	si := signed.Image(i)

	ii, err := random.Index(300 /* bytes */, 3 /* layers */, 5 /* images */)
	if err != nil {
		t.Fatalf("random.Index() = %v", err)
	}
	sii := signed.ImageIndex(ii)

	t.Run("attach SBOMs", func(t *testing.T) {
		for _, se := range []oci.SignedEntity{si, sii} {
			want := make([]byte, 300)
			rand.Read(want)

			orig, err := static.NewFile(want)
			if err != nil {
				t.Fatalf("static.NewFile() = %v", err)
			}
			se, err = AttachFileToEntity(se, "sbom", orig)
			if err != nil {
				t.Fatalf("AttachFileToEntity() = %v", err)
			}

			f, err := se.Attachment("sbom")
			if err != nil {
				t.Fatalf("Attachment(sbom) = %v", err)
			}
			got, err := f.Payload()
			if err != nil {
				t.Fatalf("Payload() = %v", err)
			}
			if !reflect.DeepEqual(want, got) {
				t.Errorf("Payload() = %v, wanted %v", got, want)
			}

			f, err = se.Attachment("gitbom")
			if err == nil {
				t.Errorf("Attachment(gitbom) = %T, wanted error", f)
			}
		}
	})

	t.Run("without duplicate detector (signature)", func(t *testing.T) {
		for _, se := range []oci.SignedEntity{si, sii} {
			orig, err := static.NewSignature(nil, "")
			if err != nil {
				t.Fatalf("static.NewSignature() = %v", err)
			}
			se, err = AttachSignatureToEntity(se, orig)
			if err != nil {
				t.Fatalf("AttachSignatureToEntity() = %v", err)
			}

			for i := 2; i < 10; i++ {
				sig, err := static.NewSignature(nil, fmt.Sprintf("%d", i))
				if err != nil {
					t.Fatalf("static.NewSignature() = %v", err)
				}

				se, err = AttachSignatureToEntity(se, sig)
				if err != nil {
					t.Fatalf("AttachSignatureToEntity() = %v", err)
				}

				sigs, err := se.Signatures()
				if err != nil {
					t.Fatalf("Signatures() = %v", err)
				}
				if sl, err := sigs.Get(); err != nil {
					t.Fatalf("Get() = %v", err)
				} else if len(sl) != i {
					t.Errorf("len(Get()) = %d, wanted %d", len(sl), i)
				}
			}
		}
	})

	t.Run("without duplicate detector (attestation)", func(t *testing.T) {
		for _, se := range []oci.SignedEntity{si, sii} {
			orig, err := static.NewAttestation([]byte("payload"))
			if err != nil {
				t.Fatalf("static.NewAttestation() = %v", err)
			}
			se, err = AttachAttestationToEntity(se, orig)
			if err != nil {
				t.Fatalf("AttachAttestationToEntity() = %v", err)
			}

			for i := 2; i < 10; i++ {
				sig, err := static.NewAttestation([]byte(fmt.Sprintf("%d", i)))
				if err != nil {
					t.Fatalf("static.NewAttestation() = %v", err)
				}

				se, err = AttachAttestationToEntity(se, sig)
				if err != nil {
					t.Fatalf("AttachAttestationToEntity() = %v", err)
				}

				atts, err := se.Attestations()
				if err != nil {
					t.Fatalf("Attestations() = %v", err)
				}
				if al, err := atts.Get(); err != nil {
					t.Fatalf("Get() = %v", err)
				} else if len(al) != i {
					t.Errorf("len(Get()) = %d, wanted %d", len(al), i)
				}
			}
		}
	})

	t.Run("with duplicate detector (signature)", func(t *testing.T) {
		for _, se := range []oci.SignedEntity{si, sii} {
			orig, err := static.NewSignature(nil, "")
			if err != nil {
				t.Fatalf("static.NewSignature() = %v", err)
			}
			se, err = AttachSignatureToEntity(se, orig)
			if err != nil {
				t.Fatalf("AttachSignatureToEntity() = %v", err)
			}

			dd := &dupe{
				sig: orig,
			}

			for i := 2; i < 10; i++ {
				sig, err := static.NewSignature(nil, fmt.Sprintf("%d", i))
				if err != nil {
					t.Fatalf("static.NewSignature() = %v", err)
				}

				se, err = AttachSignatureToEntity(se, sig, WithDupeDetector(dd))
				if err != nil {
					t.Fatalf("AttachSignatureToEntity() = %v", err)
				}

				sigs, err := se.Signatures()
				if err != nil {
					t.Fatalf("Signatures() = %v", err)
				}
				if sl, err := sigs.Get(); err != nil {
					t.Fatalf("Get() = %v", err)
				} else if len(sl) != 1 {
					t.Errorf("len(Get()) = %d, wanted %d", len(sl), i)
				}
			}
		}
	})

	t.Run("with duplicate detector (attestation)", func(t *testing.T) {
		for _, se := range []oci.SignedEntity{si, sii} {
			orig, err := static.NewAttestation([]byte("blah"))
			if err != nil {
				t.Fatalf("static.NewAttestation() = %v", err)
			}
			se, err = AttachAttestationToEntity(se, orig)
			if err != nil {
				t.Fatalf("AttachAttestationToEntity() = %v", err)
			}

			dd := &dupe{
				sig: orig,
			}

			for i := 2; i < 10; i++ {
				sig, err := static.NewAttestation([]byte(fmt.Sprintf("%d", i)))
				if err != nil {
					t.Fatalf("static.NewAttestation() = %v", err)
				}

				se, err = AttachAttestationToEntity(se, sig, WithDupeDetector(dd))
				if err != nil {
					t.Fatalf("AttachAttestationToEntity() = %v", err)
				}

				atts, err := se.Attestations()
				if err != nil {
					t.Fatalf("Attestations() = %v", err)
				}
				if al, err := atts.Get(); err != nil {
					t.Fatalf("Get() = %v", err)
				} else if len(al) != 1 {
					t.Errorf("len(Get()) = %d, wanted %d", len(al), i)
				}
			}
		}
	})

	t.Run("with erroring duplicate detector (signature)", func(t *testing.T) {
		for _, se := range []oci.SignedEntity{si, sii} {
			orig, err := static.NewSignature(nil, "")
			if err != nil {
				t.Fatalf("static.NewSignature() = %v", err)
			}
			se, err = AttachSignatureToEntity(se, orig)
			if err != nil {
				t.Fatalf("AttachSignatureToEntity() = %v", err)
			}

			want := errors.New("expected error")
			dd := &dupe{
				err: want,
			}

			for i := 2; i < 10; i++ {
				sig, err := static.NewSignature(nil, fmt.Sprintf("%d", i))
				if err != nil {
					t.Fatalf("static.NewSignature() = %v", err)
				}

				se, err = AttachSignatureToEntity(se, sig, WithDupeDetector(dd))
				if err != nil {
					t.Fatalf("AttachSignatureToEntity() = %v", err)
				}

				if _, got := se.Signatures(); !errors.Is(got, want) {
					t.Fatalf("Signatures() = %v, wanted %v", got, want)
				}
			}
		}
	})

	t.Run("with erroring duplicate detector (attestation)", func(t *testing.T) {
		for _, se := range []oci.SignedEntity{si, sii} {
			orig, err := static.NewAttestation([]byte("blah"))
			if err != nil {
				t.Fatalf("static.NewAttestation() = %v", err)
			}
			se, err = AttachAttestationToEntity(se, orig)
			if err != nil {
				t.Fatalf("AttachAttestationToEntity() = %v", err)
			}

			want := errors.New("expected error")
			dd := &dupe{
				err: want,
			}

			for i := 2; i < 10; i++ {
				sig, err := static.NewAttestation([]byte(fmt.Sprintf("%d", i)))
				if err != nil {
					t.Fatalf("static.NewAttestation() = %v", err)
				}

				se, err = AttachAttestationToEntity(se, sig, WithDupeDetector(dd))
				if err != nil {
					t.Fatalf("AttachAttestationToEntity() = %v", err)
				}

				if _, got := se.Attestations(); !errors.Is(got, want) {
					t.Fatalf("Attestations() = %v, wanted %v", got, want)
				}
			}
		}
	})
}

type dupe struct {
	sig oci.Signature
	err error
}

var _ DupeDetector = (*dupe)(nil)

// Find implements DupeDetector
func (d *dupe) Find(oci.Signatures, oci.Signature) (oci.Signature, error) {
	return d.sig, d.err
}
