//
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

package tuf

import "testing"

func TestValidBucketName(t *testing.T) {
	for _, good := range []string{
		"sigstore-tuf-root",
		"a1z",
		"0z0",
		"a-z", // internal dashes are allowed.
		"a_z", // internal underscores are allowed.
		"hello.example.com",
	} {
		t.Run(good, func(t *testing.T) {
			if !validBucketName(good) {
				t.Error("expected bucket name to be valid")
			}
		})
	}

	for _, bad := range []string{
		"goog-prefix",
		"contains-google",
		"-starts-with-dash",
		"ends-with-dash-",
		"too-much-YELLING",
	} {
		t.Run(bad, func(t *testing.T) {
			if validBucketName(bad) {
				t.Error("expected bucket name to be invalid")
			}
		})
	}
}
