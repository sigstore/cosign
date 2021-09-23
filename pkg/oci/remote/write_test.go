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
	"fmt"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/pkg/oci/mutate"
	"github.com/sigstore/cosign/pkg/oci/signed"
	"github.com/sigstore/cosign/pkg/oci/static"
)

func TestWriteSignatures(t *testing.T) {
	rw := remote.Write
	t.Cleanup(func() {
		remoteWrite = rw
	})
	i, err := random.Image(300 /* byteSize */, 7 /* layers */)
	if err != nil {
		t.Fatalf("random.Image() = %v", err)
	}
	si := signed.Image(i)

	want := 6 // Add 6 signatures
	for i := 0; i < want; i++ {
		sig, err := static.NewSignature(nil, fmt.Sprintf("%d", i))
		if err != nil {
			t.Fatalf("static.NewSignature() = %v", err)
		}
		si, err = mutate.AttachSignatureToImage(si, sig)
		if err != nil {
			t.Fatalf("SignEntity() = %v", err)
		}
	}

	ref := name.MustParseReference("gcr.io/bistroless/static:nonroot")

	remoteWrite = func(ref name.Reference, img v1.Image, options ...remote.Option) error {
		l, err := img.Layers()
		if err != nil {
			return err
		}

		if got := len(l); got != want {
			t.Errorf("got %d layers, wanted %d", got, want)
		}

		return nil
	}
	if err := WriteSignatures(ref.Context(), si); err != nil {
		t.Fatalf("WriteSignature() = %v", err)
	}
}
