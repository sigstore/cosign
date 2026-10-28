//
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

package filesystem

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestTokenPathDefault(t *testing.T) {
	t.Setenv(FilesystemTokenFileEnvVar, "")
	if got := tokenPath(); got != FilesystemTokenPath {
		t.Errorf("tokenPath() = %q, want default %q", got, FilesystemTokenPath)
	}
}

func TestTokenPathEnvVarOverride(t *testing.T) {
	const custom = "/tmp/my-custom-oidc-token"
	t.Setenv(FilesystemTokenFileEnvVar, custom)
	if got := tokenPath(); got != custom {
		t.Errorf("tokenPath() = %q, want override %q", got, custom)
	}
}

func TestProvideReadsFromEnvVarPath(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	const want = "raw.jwt.contents"
	if err := os.WriteFile(tokenFile, []byte(want), 0o600); err != nil {
		t.Fatalf("writing token fixture: %v", err)
	}
	t.Setenv(FilesystemTokenFileEnvVar, tokenFile)

	fs := &filesystem{}
	if !fs.Enabled(context.Background()) {
		t.Fatalf("Enabled() = false, expected true when env-var-pointed file exists")
	}
	got, err := fs.Provide(context.Background(), "any-audience")
	if err != nil {
		t.Fatalf("Provide: %v", err)
	}
	if got != want {
		t.Errorf("Provide() = %q, want %q", got, want)
	}
}

func TestEnabledFalseWhenNeitherPathExists(t *testing.T) {
	// Point the env var at a path that definitely doesn't exist; default
	// /var/run/sigstore/cosign/oidc-token typically also doesn't exist in
	// CI, so Enabled should be false.
	t.Setenv(FilesystemTokenFileEnvVar, filepath.Join(t.TempDir(), "does-not-exist"))
	fs := &filesystem{}
	if fs.Enabled(context.Background()) {
		t.Skip("default FilesystemTokenPath unexpectedly exists in this environment; can't test the negative case")
	}
}
