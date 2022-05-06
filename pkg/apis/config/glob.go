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
	"net/url"
	"path/filepath"
	"strings"
)

const (
	ResolvedDockerhubHost = "index.docker.io/"
	// Images such as "busybox" reside in the dockerhub "library" repository
	// The full resolved image reference would be index.docker.io/library/busybox
	DockerhubPublicRepository = "library/"
)

// GlobMatch will attempt to:
// 1. match the glob first
// 2. When the pattern is <repository>/*, therefore missing a host,
//    it should match for the resolved image digest in the form of index.docker.io/<repository>/*
// 3. When the pattern is <image>, it should match for the resolved image digest
//    against the official Dockerhub repository in the form of index.docker.io/library/*
func GlobMatch(glob, image string) (bool, error) {
	matched, err := filepath.Match(glob, image)
	if err != nil {
		return false, err
	}

	// If matched, return early
	if matched {
		return matched, nil
	}

	// If not matched, check if missing host and default to index.docker.io
	u, err := url.Parse(glob)
	if err != nil {
		return false, err
	}

	if u.Host == "" {
		dockerhubGlobPattern := ResolvedDockerhubHost

		// If the image is expected to be part of the Dockerhub official "library" repository
		if len(strings.Split(u.Path, "/")) < 2 {
			dockerhubGlobPattern += DockerhubPublicRepository
		}

		dockerhubGlobPattern += glob
		return filepath.Match(dockerhubGlobPattern, image)
	}

	return matched, nil
}
