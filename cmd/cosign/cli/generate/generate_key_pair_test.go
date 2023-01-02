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

package generate

import (
	"context"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	icos "github.com/sigstore/cosign/v2/internal/pkg/cosign"
)

func TestReadPasswordFn_env(t *testing.T) {
	t.Setenv("COSIGN_PASSWORD", "foo")
	b, err := readPasswordFn(true)()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if diff := cmp.Diff("foo", string(b)); diff != "" {
		t.Fatal(diff)
	}
}

func TestReadPasswordFn_envEmptyVal(t *testing.T) {
	t.Setenv("COSIGN_PASSWORD", "")
	b, err := readPasswordFn(true)()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(b) > 0 {
		t.Fatalf("expected empty string; got %q", string(b))
	}
}

func TestGenerationOfKeys(t *testing.T) {
	var privateKeyName = "my-test.key"
	var publicKeyName = "my-test.pub"

	t.Setenv("COSIGN_PASSWORD", "test")

	// we pass in a custom name `my-test` because the GenerateKeyPairCmd
	// doesn't care where the value comes from, only that it has a value.
	// be default it's set to `cosign`, but this is done by the CLI flag
	// framework if there is no value set by the user when running the
	// command.
	GenerateKeyPairCmd(context.Background(), "", "my-test", nil)

	checkIfFileExistsThenDelete(privateKeyName, t)
	checkIfFileExistsThenDelete(publicKeyName, t)
}

func checkIfFileExistsThenDelete(fileName string, t *testing.T) {
	fileExists, err := icos.FileExists(fileName)
	if err != nil {
		t.Fatalf("failed checking if %s exists: %v", fileName, err)
	}

	if !fileExists {
		t.Fatalf("key generation for key %s failed", fileName)
	}

	t.Logf("key generation for key %s succeeded", fileName)

	deleteKeyFile(fileName, t)
}

func deleteKeyFile(fileName string, t *testing.T) {
	t.Cleanup(func() {
		t.Logf("Removing keyfile %s...", fileName)
		os.Remove(fileName)
		t.Logf("Removed keyfile %s", fileName)
	})
}
