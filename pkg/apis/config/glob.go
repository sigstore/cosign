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

package config

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
)

const (
	ResolvedDockerhubHost = "index.docker.io/"
	// Images such as "busybox" reside in the dockerhub "library" repository
	// The full resolved image reference would be index.docker.io/library/busybox
	DockerhubPublicRepository = "library/"
)

var validGlob = regexp.MustCompile(`^[a-zA-Z0-9-_:\/\*\.]+$`)

// GlobMatch will return true if the image reference matches the requested glob pattern.
//
// If the image reference is invalid, an error will be returned.
//
// In the glob pattern, the "*" character matches any non-"/" character, and "**" matches any character, including "/".
//
// If the image is a DockerHub official image like "ubuntu" or "debian", the glob that matches it must be something like index.docker.io/library/ubuntu.
// If the image is a DockerHub used-owned image like "myuser/myapp", then the glob that matches it must be something like index.docker.io/myuser/myapp.
// This means that the glob patterns "*" will not match the image name "ubuntu", and "*/*" will not match "myuser/myapp"; the "index.docker.io" prefix is required.
//
// If the image does not specify a tag (e.g., :latest or :v1.2.3), the tag ":latest" will be assumed.
//
// Note that the tag delimiter (":") does not act as a breaking separator for the purposes of a "*" glob.
// To match any tag, the glob should end with ":**".
func GlobMatch(glob, image string) (match bool, warnings []string, err error) {
	if glob == "*/*" {
		warnings = []string{`The glob match "*/*" should be "index.docker.io/*/*"`}
		glob = "index.docker.io/*/*"
	}
	if glob == "*" {
		warnings = []string{`The glob match "*" should be "index.docker.io/library/*"`}
		glob = "index.docker.io/library/*"
	}

	ref, err := name.ParseReference(image, name.WeakValidation)
	if err != nil {
		return false, warnings, err
	}

	// Reject that glob doesn't look like a regexp
	if !validGlob.MatchString(glob) {
		return false, warnings, fmt.Errorf("invalid glob %q", glob)
	}

	// Translate glob to regexp.
	glob = strings.ReplaceAll(glob, ".", `\.`)    // . in glob means \. in regexp
	glob = strings.ReplaceAll(glob, "**", ".+")   // ** in glob means .* in regexp
	glob = strings.ReplaceAll(glob, "*", "[^/]+") // * in glob means any non-/ in regexp
	glob = fmt.Sprintf("^%s$", glob)              // glob must match the whole string

	// TODO: do we want ":" to count as a separator like "/" is?

	match, err = regexp.MatchString(glob, ref.Name())
	return match, warnings, err
}
