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

package config

import (
	"testing"
)

func TestGlobMatch(t *testing.T) {
	tests := []struct {
		glob  string
		input string
		match bool
	}{
		{glob: "foo", input: "foo", match: true},     // exact match
		{glob: "fooo*", input: "foo", match: false},  // prefix too long
		{glob: "foo*", input: "foobar", match: true}, // works
		{glob: "foo*", input: "foo", match: true},    // works
		{glob: "*", input: "foo", match: true},       // matches anything
		{glob: "*", input: "bar", match: true},       // matches anything
	}
	for _, tc := range tests {
		got := GlobMatch(tc.input, tc.glob)
		if got != tc.match {
			t.Errorf("expected %v for glob: %q input: %q", tc.match, tc.glob, tc.input)
		}
	}
}
