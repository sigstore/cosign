//
// Copyright 2025 The Sigstore Authors.
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

package attach

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSignatureBytesTrimsTrailingWhitespace(t *testing.T) {
	const want = "MEQCIGnMnU8FiEcNVIgeR6HxNp4Gaqg5q0XLSNhBO5pp+QaNAiB40iDMGGQdthm8U9qQeCAzp6ecLdKCG3R/yq5S2uMa6g=="

	dir := t.TempDir()
	sigFile := filepath.Join(dir, "signature.sig")
	// Simulate a signature file produced with `jq -r '.Base64Signature' > signature.sig`,
	// which appends a trailing newline.
	if err := os.WriteFile(sigFile, []byte(want+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	got, err := signatureBytes(sigFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("signatureBytes() = %q, want %q", string(got), want)
	}
}

func TestSignatureBytesFileWithoutTrailingWhitespaceUnaffected(t *testing.T) {
	const want = "MEQCIGnMnU8FiEcNVIgeR6HxNp4Gaqg5q0XLSNhBO5pp+QaNAiB40iDMGGQdthm8U9qQeCAzp6ecLdKCG3R/yq5S2uMa6g=="

	dir := t.TempDir()
	sigFile := filepath.Join(dir, "signature.sig")
	if err := os.WriteFile(sigFile, []byte(want), 0600); err != nil {
		t.Fatal(err)
	}

	got, err := signatureBytes(sigFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("signatureBytes() = %q, want %q", string(got), want)
	}
}
