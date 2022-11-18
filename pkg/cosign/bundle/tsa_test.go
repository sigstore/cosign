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

func TestRFC3161Timestamp(t *testing.T) {
	testCases := []struct {
		name                     string
		timestampRFC3161Entry    []byte
		expectedRFC3161Timestamp *RFC3161Timestamp
	}{{
		name:                     "nil timestamp entry",
		timestampRFC3161Entry:    nil,
		expectedRFC3161Timestamp: nil,
	}, {
		name:                  "timestamp entry",
		timestampRFC3161Entry: strfmt.Base64([]byte("signature")),
		expectedRFC3161Timestamp: &RFC3161Timestamp{
			SignedRFC3161Timestamp: strfmt.Base64([]byte("signature")),
		},
	}}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gotBundle := TimestampToRFC3161Timestamp(tc.timestampRFC3161Entry)
			if !reflect.DeepEqual(gotBundle, tc.expectedRFC3161Timestamp) {
				t.Errorf("TimestampToRFC3161Timestamp returned %v, wanted %v", gotBundle, tc.expectedRFC3161Timestamp)
			}
		})
	}
}
