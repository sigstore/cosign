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
	"reflect"
	"strings"
	"testing"
)

func TestGetImagesFromDockerfile(t *testing.T) {
	testCases := []struct {
		name         string
		fileContents string
		env          map[string]string
		expected     []string
	}{
		{
			name:         "plain",
			fileContents: `FROM gcr.io/test/image`,
			expected:     []string{"gcr.io/test/image"},
		},
		{
			name:         "tag",
			fileContents: `FROM gcr.io/test/image:latest`,
			expected:     []string{"gcr.io/test/image:latest"},
		},
		{
			name:         "tag with as",
			fileContents: `FROM golang:1.16.5 as build`,
			expected:     []string{"gcr.io/test/image:latest"},
		},
		{
			name:         "digest",
			fileContents: `FROM gcr.io/test/image@sha256:d131624e6f5d8695e9aea7a0439f7bac0fcc50051282e0c3d4d627cab8845ba5`,
			expected:     []string{"gcr.io/test/image@sha256:d131624e6f5d8695e9aea7a0439f7bac0fcc50051282e0c3d4d627cab8845ba5"},
		},
		{
			name:         "fancy-from",
			fileContents: `FROM --platform=linux/arm64 gcr.io/fancy/test/image AS fancy`,
			expected:     []string{"gcr.io/fancy/test/image"},
		},
		{
			name: "multistage",
			fileContents: `FROM build_image_1
			RUN script1
			FROM build_image_2
			RUN script2
			FROM runtime_image
			CMD bin`,
			expected: []string{"build_image_1", "build_image_2", "runtime_image"},
		},
		{
			name:         "with-arg",
			fileContents: `FROM gcr.io/${TEST_IMAGE_REPO_PATH}`,
			env: map[string]string{
				"TEST_IMAGE_REPO_PATH": "env/var/test/repo",
			},
			expected: []string{"gcr.io/env/var/test/repo"},
		},
		{
			name: "gauntlet",
			fileContents: `FROM gcr.io/${TEST_IMAGE_REPO_PATH}/one AS one
			RUN script1
			FROM gcr.io/$TEST_IMAGE_REPO_PATH/${TEST_SUBREPO}:latest
			RUN script2
			FROM --platform=linux/amd64 gcr.io/${TEST_IMAGE_REPO_PATH}/$TEST_RUNTIME_SUBREPO
			CMD bin`,
			env: map[string]string{
				"TEST_IMAGE_REPO_PATH": "gauntlet/test",
				"TEST_SUBREPO":         "two",
				"TEST_RUNTIME_SUBREPO": "runtime",
				"SOMETHING_ELSE":       "something/else",
			},
			expected: []string{"gcr.io/gauntlet/test/one", "gcr.io/gauntlet/test/two:latest", "gcr.io/gauntlet/test/runtime"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				os.Setenv(k, v)
				defer os.Unsetenv(k)
			}
			got, err := getImagesFromDockerfile(strings.NewReader(tc.fileContents))
			if err != nil {
				t.Fatalf("getImagesFromDockerfile returned error: %v", err)
			}
			if !reflect.DeepEqual(tc.expected, got) {
				t.Errorf("getImagesFromDockerfile returned %v, wanted %v", got, tc.expected)
			}
		})
	}
}
