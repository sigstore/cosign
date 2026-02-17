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

package useragent

import (
	"fmt"
	"runtime"
	"runtime/debug"

	"sigs.k8s.io/release-utils/version"
)

var (
	// uaString is meant to resemble the User-Agent sent by browsers with requests.
	// See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/User-Agent
	uaString = buildUserAgent()
)

// buildUserAgent constructs a user-agent string that includes both cosign and sigstore-go versions
func buildUserAgent() string {
	cosignVersion := version.GetVersionInfo().GitVersion
	sigstoreGoVersion := getSigstoreGoVersion()

	if sigstoreGoVersion != "" {
		return fmt.Sprintf("cosign/%s sigstore-go/%s (%s; %s)",
			cosignVersion, sigstoreGoVersion, runtime.GOOS, runtime.GOARCH)
	}

	// Fallback if sigstore-go version can't be determined
	return fmt.Sprintf("cosign/%s (%s; %s)", cosignVersion, runtime.GOOS, runtime.GOARCH)
}

// getSigstoreGoVersion retrieves the version of sigstore-go from build info
func getSigstoreGoVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}

	for _, dep := range info.Deps {
		if dep.Path == "github.com/sigstore/sigstore-go" {
			return dep.Version
		}
	}

	return ""
}

// Get returns the User-Agent string which `cosign` should send with HTTP requests.
func Get() string {
	return uaString
}
