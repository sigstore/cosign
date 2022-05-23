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
	"reflect"
	"testing"
)

func TestGlobMatch(t *testing.T) {
	for _, c := range []struct {
		image, glob  string
		wantMatch    bool
		wantWarnings []string
		wantErr      bool
	}{
		{image: "foo", glob: "index.docker.io/library/foo:latest", wantMatch: true},
		{image: "foo", glob: "index.docker.io/library/foo:*", wantMatch: true},
		{image: "foo", glob: "index.docker.io/library/*", wantMatch: true},
		{image: "foo", glob: "index.docker.io/library/*:latest", wantMatch: true},
		{image: "foo", glob: "index.docker.io/*/*", wantMatch: true},
		{image: "foo", glob: "index.docker.io/**", wantMatch: true},
		{image: "foo", glob: "index.docker.**", wantMatch: true},
		{image: "foo", glob: "inde**", wantMatch: true},
		{image: "foo", glob: "**", wantMatch: true},
		{image: "foo", glob: "foo", wantMatch: false}, // must have index.docker.io/library prefix.
		{image: "myuser/myapp", glob: "index.docker.io/myuser/myapp:latest", wantMatch: true},
		{image: "myuser/myapp", glob: "index.docker.io/myuser/myapp:*", wantMatch: true},
		{image: "myuser/myapp", glob: "index.docker.io/myuser/*", wantMatch: true},
		{image: "myuser/myapp", glob: "index.docker.io/myuser/*:latest", wantMatch: true},
		{image: "myuser/myapp", glob: "index.docker.io/*/*", wantMatch: true},
		{image: "myuser/myapp", glob: "index.docker.io/**", wantMatch: true},
		{image: "myuser/myapp", glob: "index.docker.**", wantMatch: true},
		{image: "myuser/myapp", glob: "inde**", wantMatch: true},
		{image: "myuser/myapp", glob: "**", wantMatch: true},
		{image: "myuser/myapp", glob: "myuser/myapp", wantMatch: false}, // must have index.docker.io prefix.
		{image: "ghcr.io/foo/bar", glob: "ghcr.io/*/*", wantMatch: true},
		{image: "ghcr.io/foo/bar", glob: "ghcr.io/**", wantMatch: true},
		{image: "ghcr.io/foo", glob: "ghcr.io/*/*", wantMatch: false}, // doesn't match second *
		{image: "ghcr.io/foo", glob: "ghcr.io/**", wantMatch: true},
		{image: "ghcr.io/foo", glob: "ghc**", wantMatch: true},
		{image: "ghcr.io/foo", glob: "**", wantMatch: true},
		{image: "ghcr.io/foo", glob: "*/**", wantMatch: true},
		{image: "prefix-ghcr.io/foo", glob: "ghcr.io/foo", wantMatch: false},     // glob starts at beginning.
		{image: "ghcr.io/foo-suffix", glob: "ghcr.io/foo", wantMatch: false},     // glob ends at the end.
		{image: "ghcrxio/foo", glob: "ghcr.io/**", wantMatch: false},             // dots in glob are replaced with \., not treated as regexp .
		{image: "invalid&name", glob: "**", wantMatch: false, wantErr: true},     // invalid refs are not matched.
		{image: "invalid-glob", glob: ".+", wantMatch: false, wantErr: true},     // invalid globs are rejected.
		{image: "invalid-glob", glob: "[a-z]*", wantMatch: false, wantErr: true}, // invalid globs are rejected.
		{image: "foo", glob: "*", wantMatch: true,
			wantWarnings: []string{`The glob match "*" should be "index.docker.io/library/*"`}},
		{image: "myuser/myapp", glob: "*/*", wantMatch: true,
			wantWarnings: []string{`The glob match "*/*" should be "index.docker.io/*/*"`}},
	} {
		t.Run(c.image+"|"+c.glob, func(t *testing.T) {
			match, warnings, err := GlobMatch(c.glob, c.image)
			if match != c.wantMatch {
				t.Errorf("match: got %t, want %t", match, c.wantMatch)
			}
			if !reflect.DeepEqual(warnings, c.wantWarnings) {
				t.Errorf("warnings: got %v, want %v", warnings, c.wantWarnings)
			}
			if gotErr := err != nil; gotErr != c.wantErr {
				t.Errorf("err: got %v, want %t", err, c.wantErr)
			}
		})
	}
}
