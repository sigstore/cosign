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

package blob

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"runtime"
	"strings"
	"testing"
)

func TestLoadFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping on Windows due to https://github.com/golang/go/issues/51442")
	}
	temp := t.TempDir()
	fname := "filename.txt"
	path := path.Join(temp, fname)
	data := []byte("test")
	defer os.Remove(path)
	os.WriteFile(path, data, 0400)

	// absolute path
	actual, err := LoadFileOrURL(path)
	if err != nil {
		t.Errorf("Reading from absolute path %s failed: %v", path, err)
	} else if !bytes.Equal(actual, data) {
		t.Errorf("LoadFileOrURL(absolute path) = '%s'; want '%s'", actual, data)
	}

	if err = os.Chdir(temp); err != nil {
		t.Fatalf("Chdir('%s'): %v", temp, err)
	}
	actual, err = LoadFileOrURL(fname)
	if err != nil {
		t.Errorf("Reading from relative path %s failed: %v", fname, err)
	} else if !bytes.Equal(actual, data) {
		t.Errorf("LoadFileOrURL(relative path) = '%s'; want '%s'", actual, data)
	}
}

func TestLoadURL(t *testing.T) {
	data := []byte("test")

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Write(data)
	}))
	defer server.Close()

	actual, err := LoadFileOrURL(server.URL)
	if err != nil {
		t.Errorf("Reading from HTTP failed: %v", err)
	} else if !bytes.Equal(actual, data) {
		t.Errorf("LoadFileOrURL(HTTP) = '%s'; want '%s'", actual, data)
	}

	os.Setenv("MY_ENV_VAR", string(data))
	actual, err = LoadFileOrURL("env://MY_ENV_VAR")
	if err != nil {
		t.Errorf("Reading from environment failed: %v", err)
	} else if !bytes.Equal(actual, data) {
		t.Errorf("LoadFileOrURL(env) = '%s'; want '%s'", actual, data)
	}

	os.Setenv("MY_ENV_VAR", "")
	actual, err = LoadFileOrURL("env://MY_ENV_VAR")
	if err != nil {
		t.Errorf("Reading from environment failed: %v", err)
	} else if !bytes.Equal(actual, make([]byte, 0)) {
		t.Errorf("LoadFileOrURL(env) = '%s'; should be empty", actual)
	}

	os.Unsetenv("MY_ENV_VAR")
	_, err = LoadFileOrURL("env://MY_ENV_VAR")
	if err == nil {
		t.Error("LoadFileOrURL(): expected error for unset env var")
	}

	_, err = LoadFileOrURL("invalid://url")
	if err == nil {
		t.Error("LoadFileOrURL(): expected error for invalid scheme")
	}
}

func TestLoadURLWithChecksum(t *testing.T) {
	data := []byte("test")

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Write(data)
	}))
	defer server.Close()

	// default behavior with sha256
	actual, err := LoadFileOrURLWithChecksum(
		server.URL,
		"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
	)
	if err != nil {
		t.Errorf("Reading from HTTP failed: %v", err)
	} else if !bytes.Equal(actual, data) {
		t.Errorf("LoadFileOrURL(HTTP) = '%s'; want '%s'", actual, data)
	}

	// override checksum algo to sha512
	actual, err = LoadFileOrURLWithChecksum(
		server.URL,
		"sha512:ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff",
	)
	if err != nil {
		t.Errorf("Reading from HTTP failed: %v", err)
	} else if !bytes.Equal(actual, data) {
		t.Errorf("LoadFileOrURL(HTTP) = '%s'; want '%s'", actual, data)
	}

	// ensure it fails with the wrong checksum
	_, err = LoadFileOrURLWithChecksum(
		server.URL,
		"certainly not a correct checksum value",
	)
	if err == nil || !strings.Contains(err.Error(), "incorrect checksum") {
		t.Errorf("Expected an 'incorrect checksum' error, got: %v", err)
	}

	// ensure it fails with incorrect algorithm
	_, err = LoadFileOrURLWithChecksum(
		server.URL,
		"sha321123:foobar",
	)
	if err == nil || !strings.Contains(err.Error(), "unsupported checksum") {
		t.Errorf("Expected an 'unsupported checksum' error, got: %v", err)
	}
}
