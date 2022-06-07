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

package cosign

import (
	"context"
	"testing"
)

func TestGetRekorPubKeys(t *testing.T) {
	keys, err := GetRekorPubs(context.Background(), nil)
	if err != nil {
		t.Errorf("Unexpected error calling GetRekorPubs, expected nil: %v", err)
	}
	if len(keys) == 0 {
		t.Errorf("expected 1 or more keys, got 0")
	}
	// check that the mapping of key digest to key is correct
	for logID, key := range keys {
		expectedLogID, err := getLogID(key.PubKey)
		if err != nil {
			t.Fatalf("unexpected error generated log ID: %v", err)
		}
		if logID != expectedLogID {
			t.Fatalf("key digests are not equal")
		}
	}
}
