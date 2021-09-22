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
	"testing"

	"github.com/sigstore/cosign/internal/oci/empty"
	"github.com/sigstore/cosign/internal/oci/static"
)

func TestAppendSignatures(t *testing.T) {
	base := empty.Signatures()

	s1, err := static.NewSignature([]byte{}, "s1")
	if err != nil {
		t.Fatalf("NewSignature() = %v", err)
	}
	s2, err := static.NewSignature([]byte{}, "s2")
	if err != nil {
		t.Fatalf("NewSignature() = %v", err)
	}
	s3, err := static.NewSignature([]byte{}, "s3")
	if err != nil {
		t.Fatalf("NewSignature() = %v", err)
	}

	oneSig, err := AppendSignatures(base, s1)
	if err != nil {
		t.Fatalf("AppendSignatures() = %v", err)
	}

	twoSig, err := AppendSignatures(oneSig, s2)
	if err != nil {
		t.Fatalf("AppendSignatures() = %v", err)
	}

	threeSig, err := AppendSignatures(oneSig, s2, s3)
	if err != nil {
		t.Fatalf("AppendSignatures() = %v", err)
	}

	if sl, err := oneSig.Get(); err != nil {
		t.Fatalf("Get() = %v", err)
	} else if got, want := len(sl), 1; got != want {
		t.Errorf("len(Get()) = %d, wanted %d", got, want)
	}

	if sl, err := twoSig.Get(); err != nil {
		t.Fatalf("Get() = %v", err)
	} else if got, want := len(sl), 2; got != want {
		t.Errorf("len(Get()) = %d, wanted %d", got, want)
	}

	if sl, err := threeSig.Get(); err != nil {
		t.Fatalf("Get() = %v", err)
	} else if got, want := len(sl), 3; got != want {
		t.Errorf("len(Get()) = %d, wanted %d", got, want)
	}
}
