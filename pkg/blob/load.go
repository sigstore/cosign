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
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func LoadFileOrURL(fileRef string) ([]byte, error) {
	var raw []byte
	var err error
	parts := strings.SplitAfterN(fileRef, "://", 2)
	if len(parts) == 2 {
		scheme := parts[0]
		switch scheme {
		case "http://":
			fallthrough
		case "https://":
			// #nosec G107
			resp, err := http.Get(fileRef)
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()
			raw, err = io.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("loading URL: unrecognized scheme: %s", scheme)
		}
	} else {
		raw, err = os.ReadFile(filepath.Clean(fileRef))
		if err != nil {
			return nil, err
		}
	}
	return raw, nil
}
