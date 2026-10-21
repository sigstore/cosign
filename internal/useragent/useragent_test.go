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
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
)

func TestGet(t *testing.T) {
	ua := Get()
	if !strings.HasPrefix(ua, "cosign/") {
		t.Errorf("User-Agent should start with 'cosign/', got: %s", ua)
	}
	if strings.Contains(ua, "sigstore-go") {
		t.Errorf("User-Agent should not contain 'sigstore-go', got: %s", ua)
	}
	if !strings.HasSuffix(ua, fmt.Sprintf("(%s; %s)", runtime.GOOS, runtime.GOARCH)) {
		t.Errorf("User-Agent should end with OS and architecture, got: %s", ua)
	}
}

func TestBuildSigstoreGoUserAgent(t *testing.T) {
	platform := fmt.Sprintf("(%s; %s)", runtime.GOOS, runtime.GOARCH)
	tests := []struct {
		name      string
		sgVersion string
		want      string
	}{
		{
			name:      "with sigstore-go version",
			sgVersion: "v1.3.0",
			want:      "cosign/v3.0.0 sigstore-go/v1.3.0 " + platform,
		},
		{
			name:      "without sigstore-go version",
			sgVersion: "",
			want:      "cosign/v3.0.0 sigstore-go " + platform,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildSigstoreGoUserAgent("v3.0.0", tt.sgVersion); got != tt.want {
				t.Errorf("buildSigstoreGoUserAgent() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTransport(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("User-Agent")
	}))
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	// sigstore-go sets its own User-Agent with Header.Add; it must be replaced.
	req.Header.Add("User-Agent", "sigstore-go/v0.0.0")

	client := &http.Client{Transport: NewSigstoreGoTransport(nil)}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if got != GetWithSigstoreGo() {
		t.Errorf("User-Agent = %q, want %q", got, GetWithSigstoreGo())
	}
	if req.Header.Get("User-Agent") != "sigstore-go/v0.0.0" {
		t.Error("Transport should not mutate the original request")
	}
}
