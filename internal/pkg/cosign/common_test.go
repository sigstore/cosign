//
// Copyright 2022 The Sigstore Authors.
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

package cosign

import (
	"bytes"
	"crypto/sha256"
	"io"
	"os"
	"testing"
)

func Test_FileExists(t *testing.T) {
	tmpFile, err := os.CreateTemp(os.TempDir(), "cosign_test.txt")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		path    string
		exists  bool
		wantErr bool
	}{
		{"file exists", tmpFile.Name(), true, false},
		{"file does not exist", "testt.txt", false, false},
		{"other error e.g cannot access file", "\000x", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FileExists(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("FileExists() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.exists {
				t.Errorf("FileExists() = %v, want %v", got, tt.exists)
			}
		})
	}
}

func Test_HashReader(t *testing.T) {
	input := []byte("hello world")
	r := NewHashReader(bytes.NewReader(input), sha256.New())

	got, err := io.ReadAll(&r)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, input) {
		t.Errorf("io.ReadAll returned %s, want %s", got, input)
	}

	gotHash := r.Sum(nil)
	if hash := sha256.Sum256(input); !bytes.Equal(gotHash, hash[:]) {
		t.Errorf("Sum returned %s, want %s", gotHash, hash)
	}
}
