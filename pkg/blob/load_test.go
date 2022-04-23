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
	"testing"
)

func TestLoadFileOrURL(t *testing.T) {
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

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Write(data)
	}))
	defer server.Close()

	actual, err = LoadFileOrURL(server.URL)
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
