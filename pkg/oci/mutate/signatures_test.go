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
	"errors"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/empty"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
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

	oneSig, err := AppendSignatures(base, false, s1)
	if err != nil {
		t.Fatalf("AppendSignatures() = %v", err)
	}

	twoSig, err := AppendSignatures(oneSig, false, s2)
	if err != nil {
		t.Fatalf("AppendSignatures() = %v", err)
	}

	threeSig, err := AppendSignatures(oneSig, true, s2, s3)
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

	if testCfg, err := threeSig.ConfigFile(); err != nil {
		t.Fatalf("ConfigFile() = %v", err)
	} else if testCfg.Created.IsZero() {
		t.Errorf("Date of Signature was Zero")
	}

	if testDefaultCfg, err := twoSig.ConfigFile(); err != nil {
		t.Fatalf("ConfigFile() = %v", err)
	} else if !testDefaultCfg.Created.IsZero() {
		t.Errorf("Date of Signature was Zero")
	}
}

func TestReplaceSignatures(t *testing.T) {
	base := empty.Signatures()

	s1, err := static.NewSignature([]byte{}, "s1")
	if err != nil {
		t.Fatalf("NewSignature() = %v", err)
	}

	oneSig, err := AppendSignatures(base, false, s1)
	if err != nil {
		t.Fatalf("AppendSignatures() = %v", err)
	}
	replaceSig, err := ReplaceSignatures(oneSig)
	if err != nil {
		t.Fatalf("ReplaceSignatures() = %v", err)
	}
	if sl, err := replaceSig.Get(); err != nil {
		t.Fatalf("Get() = %v", err)
	} else if got, want := len(sl), 1; got != want {
		t.Errorf("len(Get()) = %d, wanted %d", got, want)
	}
	if mt, err := replaceSig.MediaType(); err != nil {
		t.Fatalf("MediaType() = %v", err)
	} else if got, want := mt, types.OCIManifestSchema1; got != want {
		t.Errorf("MediaType() = %v, wanted %v", got, want)
	}
}

func TestGet(t *testing.T) {
	tests := []struct {
		name         string
		baseLayers   int
		appendLayers int
		wantError    error
	}{
		{
			name:         "within limit",
			baseLayers:   1,
			appendLayers: 1,
			wantError:    nil,
		},
		{
			name:         "base exceeds limit",
			baseLayers:   2000,
			appendLayers: 1,
			wantError:    errors.New("number of layers (2001) exceeded the limit (1000)"),
		},
		{
			name:         "append exceeds limit",
			baseLayers:   1,
			appendLayers: 1300,
			wantError:    errors.New("number of layers (1301) exceeded the limit (1000)"),
		},
		{
			name:         "sum exceeds limit",
			baseLayers:   666,
			appendLayers: 666,
			wantError:    errors.New("number of layers (1332) exceeded the limit (1000)"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sa := sigAppender{
				base: &mockOCISignatures{
					signatures: make([]oci.Signature, test.baseLayers),
				},
				sigs: make([]oci.Signature, test.appendLayers),
			}
			_, err := sa.Get()
			if test.wantError != nil && test.wantError.Error() != err.Error() {
				t.Fatalf("Get() = %v, wanted %v", err, test.wantError)
			}
			if test.wantError == nil && err != nil {
				t.Fatalf("Get() = %v, wanted %v", err, test.wantError)
			}
		})
	}
}

type mockOCISignatures struct {
	v1.Image
	signatures []oci.Signature
}

func (m *mockOCISignatures) Get() ([]oci.Signature, error) {
	return m.signatures, nil
}
