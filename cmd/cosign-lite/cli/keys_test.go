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

package cli

import (
	"path/filepath"
	"testing"

	icos "github.com/sigstore/cosign/v3/internal/pkg/cosign"
)

func TestGetPass_env(t *testing.T) {
	t.Setenv("COSIGN_PASSWORD", "foo")
	b, err := getPass(true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(b) != "foo" {
		t.Fatalf("expected %q; got %q", "foo", string(b))
	}
}

func TestGetPass_envEmptyVal(t *testing.T) {
	t.Setenv("COSIGN_PASSWORD", "")
	b, err := getPass(true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(b) > 0 {
		t.Fatalf("expected empty bytes; got %q", string(b))
	}
}

func TestGenerationOfKeys(t *testing.T) {
	td := t.TempDir()
	privateKeyPath := filepath.Join(td, "my-test.key")
	publicKeyPath := filepath.Join(td, "my-test.pub")

	t.Setenv("COSIGN_PASSWORD", "test")

	prefix := filepath.Join(td, "my-test")
	err := generateKeyPair(prefix, getPass)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check files exist
	for _, fn := range []string{privateKeyPath, publicKeyPath} {
		fileExists, err := icos.FileExists(fn)
		if err != nil {
			t.Fatalf("failed checking if %s exists: %v", fn, err)
		}
		if !fileExists {
			t.Fatalf("key generation for key %s failed", fn)
		}
		t.Logf("key generation for key %s succeeded", fn)
	}
}
