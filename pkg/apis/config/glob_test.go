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
	"runtime"
	"testing"
)

func TestGlobMatch(t *testing.T) {
	tests := []struct {
		glob         string
		input        string
		match        bool
		errString    string
		windowsMatch *struct {
			match bool
		}
	}{
		{glob: "foo", input: "foo", match: true},     // exact match
		{glob: "fooo*", input: "foo", match: false},  // prefix too long
		{glob: "foo*", input: "foobar", match: true}, // works
		{glob: "foo*", input: "foo", match: true},    // works
		{glob: "*", input: "foo", match: true},       // matches anything
		{glob: "*", input: "bar", match: true},       // matches anything
		{glob: "*foo*", input: "1foo2", match: true}, // matches wildcard around
		{glob: "*repository/*", input: "repository/image", match: true},
		{glob: "*.repository/*", input: "other.repository/image", match: true},
		{glob: "repository/*", input: "repository/image", match: true},
		{glob: "repository/*", input: "other.repository/image", match: false},
		{glob: "repository/*", input: "index.docker.io/repository/image", match: true}, // Testing resolved digest
		{glob: "image", input: "index.docker.io/library/image", match: true},           // Testing resolved digest and official dockerhub public repository
		{glob: "[", input: "[", match: false, errString: "syntax error in pattern"},    // Invalid glob pattern
		{glob: "gcr.io/projectsigstore/*", input: "gcr.io/projectsigstore/cosign", match: true},
		{glob: "gcr.io/projectsigstore/*", input: "us.gcr.io/projectsigstore/cosign", match: false},
		{glob: "*gcr.io/projectsigstore/*", input: "gcr.io/projectsigstore/cosign", match: true},
		{glob: "*gcr.io/projectsigstore/*", input: "gcr.io/projectsigstore2/cosign", match: false},
		{glob: "*gcr.io/*/*", input: "us.gcr.io/projectsigstore/cosign", match: true}, // Does match with multiple '*'
		{glob: "us.gcr.io/*/*", input: "us.gcr.io/projectsigstore/cosign", match: true},
		{glob: "us.gcr.io/*/*", input: "gcr.io/projectsigstore/cosign", match: false},
		{glob: "*.gcr.io/*/*", input: "asia.gcr.io/projectsigstore/cosign", match: true},
		{glob: "*.gcr.io/*/*", input: "gcr.io/projectsigstore/cosign", match: false},
		// Does not match since '*' only handles until next non-separator character '/'
		// On Windows, '/' is not the separator and therefore it passes
		{glob: "*gcr.io/*", input: "us.gcr.io/projectsigstore/cosign", match: false, windowsMatch: &struct{ match bool }{match: true}},
	}
	for _, tc := range tests {
		got, err := GlobMatch(tc.glob, tc.input)

		if tc.errString != "" {
			if tc.errString != err.Error() {
				t.Errorf("expected %s for error: %s", tc.errString, err.Error())
			}
		} else if err != nil {
			t.Errorf("unexpected error: %v for glob: %q input: %q", err, tc.glob, tc.input)
		}

		want := tc.match

		// If OS is Windows, check if there is a different expected match value
		if runtime.GOOS == "windows" && tc.windowsMatch != nil {
			want = tc.windowsMatch.match
		}

		if got != want {
			t.Errorf("expected %v for glob: %q input: %q", want, tc.glob, tc.input)
		}
	}
}
