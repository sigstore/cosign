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
	"net/http"
	"runtime"
	"runtime/debug"

	"sigs.k8s.io/release-utils/version"
)

const sigstoreGoModule = "github.com/sigstore/sigstore-go"

var (
	// uaString is meant to resemble the User-Agent sent by browsers with requests.
	// See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/User-Agent
	uaString = fmt.Sprintf("cosign/%s (%s; %s)", version.GetVersionInfo().GitVersion, runtime.GOOS, runtime.GOARCH)

	// sigstoreGoUAString is sent with requests made through sigstore-go.
	sigstoreGoUAString = buildSigstoreGoUserAgent(version.GetVersionInfo().GitVersion, sigstoreGoVersion())
)

// Get returns the User-Agent string which `cosign` should send with HTTP requests.
func Get() string {
	return uaString
}

// GetWithSigstoreGo returns the User-Agent string which `cosign` should send
// with HTTP requests made through sigstore-go.
func GetWithSigstoreGo() string {
	return sigstoreGoUAString
}

func buildSigstoreGoUserAgent(cosignVersion, sgVersion string) string {
	if sgVersion == "" {
		return fmt.Sprintf("cosign/%s sigstore-go (%s; %s)", cosignVersion, runtime.GOOS, runtime.GOARCH)
	}
	return fmt.Sprintf("cosign/%s sigstore-go/%s (%s; %s)", cosignVersion, sgVersion, runtime.GOOS, runtime.GOARCH)
}

// sigstoreGoVersion returns the sigstore-go module version from the build info,
// or an empty string if it is not available (e.g. in test binaries).
func sigstoreGoVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, dep := range info.Deps {
		if dep.Path == sigstoreGoModule {
			return dep.Version
		}
	}
	return ""
}

// Transport wraps an http.RoundTripper and sets the User-Agent header on
// every request, replacing any value already set.
type Transport struct {
	UserAgent string
	Base      http.RoundTripper
}

// NewSigstoreGoTransport returns a Transport that sets the sigstore-go
// User-Agent. If base is nil, http.DefaultTransport is used.
func NewSigstoreGoTransport(base http.RoundTripper) *Transport {
	return &Transport{UserAgent: GetWithSigstoreGo(), Base: base}
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	req = req.Clone(req.Context())
	req.Header.Set("User-Agent", t.UserAgent)
	return base.RoundTrip(req)
}
