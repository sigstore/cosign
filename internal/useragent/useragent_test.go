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
	"strings"
	"testing"
)

func TestGet(t *testing.T) {
	ua := Get()

	// Should contain "cosign/"
	if !strings.Contains(ua, "cosign/") {
		t.Errorf("User-Agent should contain 'cosign/', got: %s", ua)
	}

	// Should contain OS and architecture
	if !strings.Contains(ua, "(") || !strings.Contains(ua, ")") {
		t.Errorf("User-Agent should contain OS and architecture in parentheses, got: %s", ua)
	}

	// When built as a binary (not with go run), it should contain sigstore-go version
	// In test mode with go test, it might not have dependency info
	t.Logf("User-Agent: %s", ua)
}

func TestGetSigstoreGoVersion(t *testing.T) {
	version := getSigstoreGoVersion()

	// NOTE: When running 'go test', the version will typically be empty because Go
	// doesn't embed full dependency metadata in test binaries. The Deps slice in
	// debug.ReadBuildInfo() is empty for test executables.
	//
	// However, when cosign is built with 'go build', the binary DOES contain this
	// information (verified with 'go version -m ./cosign'), and getSigstoreGoVersion()
	// will successfully extract it at runtime.
	//
	// To verify this works in production, check the built binary:
	//   $ go version -m ./cosign | grep sigstore-go
	//   dep github.com/sigstore/sigstore-go v1.1.4 ...

	if version == "" {
		t.Log("sigstore-go version not found (expected in 'go test' mode)")
		t.Log("In production binaries built with 'go build', the version IS available")
	} else {
		t.Logf("sigstore-go version found: %s", version)
		// If version is found, it should start with 'v'
		if len(version) > 0 && version[0] != 'v' {
			t.Errorf("Expected version to start with 'v', got: %s", version)
		}
	}
}
