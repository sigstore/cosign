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

package cli

import (
	"testing"
)

// Tests correctly formatted emails do not fail validEmail call
// Tests incorrectly formatted emails do not pass validEmail call
func TestEmailValid(t *testing.T) {
	goodEmail := "foo@foo.com"
	strongBadEmail := "foofoocom"

	if !validEmail(goodEmail) {
		t.Errorf("correct email %s, failed valid check", goodEmail)
	} else if validEmail(strongBadEmail) {
		t.Errorf("bad email %s, passed valid check", strongBadEmail)
	}
}
