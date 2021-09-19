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

	"github.com/google/go-containerregistry/pkg/v1/random"
)

func TestImage(t *testing.T) {
	i, err := random.Image(300 /* bytes */, 5 /* layers */)
	if err != nil {
		t.Fatalf("random.Image() = %v", err)
	}

	si := Image(i)

	sigs, err := si.Signatures()
	if err != nil {
		t.Fatalf("Signatures() = %v", err)
	}

	if sl, err := sigs.Get(); err != nil {
		t.Errorf("Get() = %v", err)
	} else if got, want := len(sl), 0; got != want {
		t.Errorf("len(Get()) = %d, wanted %d", got, want)
	}

	if _, err := si.Attestations(); err == nil {
		t.Error("Need coverage for attestations!")
	}
}
