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

package empty

import (
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
)

func TestSignedImage(t *testing.T) {
	tests := []struct {
		ref       string
		digestStr string
		digestErr string
	}{
		{
			ref:       "hello-world:latest",
			digestErr: "digest not available",
		},
		{
			ref:       "hello-world@sha256:e1c082e3d3c45cccac829840a25941e679c25d438cc8412c2fa221cf1a824e6a",
			digestStr: "sha256:e1c082e3d3c45cccac829840a25941e679c25d438cc8412c2fa221cf1a824e6a",
		},
	}
	for _, test := range tests {
		ref, err := name.ParseReference(test.ref)
		if err != nil {
			t.Errorf("failed to parse ref \"%s\": %v", test.ref, err)
			continue
		}
		se, err := SignedImage(ref)
		if err != nil {
			t.Errorf("failed to create signed image for \"%s\": %v", test.ref, err)
			continue
		}
		d, err := se.Digest()
		if (err == nil && test.digestErr != "") ||
			(err != nil && test.digestErr == "") ||
			(err != nil && test.digestErr != "" && err.Error() != test.digestErr) {
			t.Errorf("digest error mismatch for \"%s\": expected %s, saw %v", test.ref, test.digestErr, err)
		}
		if test.digestStr != "" && d.String() != test.digestStr {
			t.Errorf("digest mismatch for \"%s\": expected %s, saw %s", test.ref, test.digestStr, d.String())
		}
		_, err = se.Signatures()
		if err != nil {
			t.Errorf("failed to get signatures for %s: %v", test.ref, err)
		}
		_, err = se.Attestations()
		if err != nil {
			t.Errorf("failed to get attestations for %s: %v", test.ref, err)
		}
	}
}
