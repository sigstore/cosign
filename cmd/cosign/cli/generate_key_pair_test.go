//
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

package cli

import (
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestReadPasswordFn_env(t *testing.T) {
	os.Setenv("COSIGN_PASSWORD", "foo")
	defer os.Unsetenv("COSIGN_PASSWORD")
	b, err := readPasswordFn(true)()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if diff := cmp.Diff("foo", string(b)); diff != "" {
		t.Fatal(diff)
	}
}

func TestReadPasswordFn_envEmptyVal(t *testing.T) {
	os.Setenv("COSIGN_PASSWORD", "")
	defer os.Unsetenv("COSIGN_PASSWORD")
	b, err := readPasswordFn(true)()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(b) > 0 {
		t.Fatalf("expected empty string; got %q", string(b))
	}
}
