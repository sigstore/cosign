// Copyright 2026 The Sigstore Authors.
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

	"sigs.k8s.io/release-utils/version"
)

var (
	// uaString is meant to resemble the User-Agent sent by browsers with requests.
	// See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/User-Agent
	uaString = fmt.Sprintf("cosign/%s (%s; %s)", version.GetVersionInfo().GitVersion, runtime.GOOS, runtime.GOARCH)
)

// Get returns the User-Agent string which `cosign` should send with HTTP requests.
// Requests made through sigstore-go append sigstore-go/<version> to it.
func Get() string {
	return uaString
}
