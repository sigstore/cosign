// Copyright 2022 The Sigstore Authors.
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

package bundle

import (
	"reflect"
	"testing"

	"github.com/go-openapi/strfmt"
)

func TestTSABundle(t *testing.T) {
	testCases := []struct {
		name                  string
		timestampRFC3161Entry []byte
		expectedTSABundle     *TSABundle
	}{{
		name:                  "nil timestamp entry",
		timestampRFC3161Entry: nil,
		expectedTSABundle:     nil,
	}, {
		name:                  "timestamp entry",
		timestampRFC3161Entry: strfmt.Base64([]byte("signature")),
		expectedTSABundle: &TSABundle{
			SignedRFC3161Timestamp: strfmt.Base64([]byte("signature")),
		},
	}}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gotBundle := TimestampToTSABundle(tc.timestampRFC3161Entry)
			if !reflect.DeepEqual(gotBundle, tc.expectedTSABundle) {
				t.Errorf("TimestampToTSABundle returned %v, wanted %v", gotBundle, tc.expectedTSABundle)
			}
		})
	}
}
