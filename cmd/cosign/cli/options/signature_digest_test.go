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

package options

import (
	"crypto"
	"testing"
)

func TestSignatureDigestOptionsHashAlgorithm(t *testing.T) {
	tests := []struct {
		name         string
		algorithm    string
		expectedHash crypto.Hash
		expectErr    bool
	}{
		{name: "unset defers to caller-specific default", algorithm: "", expectedHash: 0},
		{name: "sha256", algorithm: "sha256", expectedHash: crypto.SHA256},
		{name: "sha512", algorithm: "sha512", expectedHash: crypto.SHA512},
		{name: "case and whitespace insensitive", algorithm: " SHA512 ", expectedHash: crypto.SHA512},
		{name: "unknown algorithm errors", algorithm: "sha1", expectErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &SignatureDigestOptions{AlgorithmName: tt.algorithm}
			hash, err := o.HashAlgorithm()
			if tt.expectErr {
				if err == nil {
					t.Fatalf("expected error for algorithm %q", tt.algorithm)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if hash != tt.expectedHash {
				t.Fatalf("expected hash %v, got %v", tt.expectedHash, hash)
			}
		})
	}
}
