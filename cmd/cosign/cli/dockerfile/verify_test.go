// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package dockerfile

import (
	"context"
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
			fileContents: `FROM gcr.io/test/image:1.16.5 as build`,
			expected:     []string{"gcr.io/test/image:1.16.5"},
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
			name: "with-value-from-arg",
			fileContents: `ARG IMAGE=gcr.io/someorg/someimage
FROM ${IMAGE}`,
			expected: []string{"gcr.io/someorg/someimage"},
		},
		{
			name: "with-value-from-env",
			fileContents: `ENV IMAGE=gcr.io/someorg/someimage
FROM ${IMAGE}`,
			expected: []string{"gcr.io/someorg/someimage"},
		},
		{
			name: "with-multiple-values-from-env",
			fileContents: `ENV IMAGE_ONE=gcr.io/someorg/someimage IMAGE_TWO=gcr.io/someorg/coolimage
FROM ${IMAGE_ONE}
FROM ${IMAGE_TWO}`,
			expected: []string{"gcr.io/someorg/someimage", "gcr.io/someorg/coolimage"},
		},
		{
			name: "with-value-from-arg-from-env",
			fileContents: `ARG IMAGE=${THING}
FROM ${IMAGE}`,
			expected: []string{"gcr.io/someorg/coolimage"},
			env: map[string]string{
				"THING": "gcr.io/someorg/coolimage",
			},
		},
		{
			name:         "image-in-copy",
			fileContents: `COPY --from=gcr.io/someorg/someimage /var/www/html /app`,
			expected:     []string{"gcr.io/someorg/someimage"},
		},
		{
			name: "image-in-copy-with-env",
			fileContents: `ENV IMAGE_HERE=gcr.io/someorg/someimage
COPY --from=${IMAGE_HERE} /var/www/html /app`,
			expected: []string{"gcr.io/someorg/someimage"},
		},
		{
			name: "copy-dont-include-prepare-stage-as-images",
			fileContents: `FROM gcr.io/someorg/coolimage AS prepare
FROM gcr.io/someorg/someimage AS final
COPY --from=prepare /app /app`,
			expected: []string{"gcr.io/someorg/coolimage", "gcr.io/someorg/someimage"},
		},
		{
			name: "gauntlet",
			fileContents: `FROM gcr.io/${TEST_IMAGE_REPO_PATH}/one AS one
RUN script1
FROM gcr.io/$TEST_IMAGE_REPO_PATH/${TEST_SUBREPO}:latest
RUN script2
FROM --platform=linux/amd64 gcr.io/${TEST_IMAGE_REPO_PATH}/$TEST_RUNTIME_SUBREPO
COPY --from=gcr.io/someorg/someimage /etc/config /app/etc/config
CMD bin`,
			env: map[string]string{
				"TEST_IMAGE_REPO_PATH": "gauntlet/test",
				"TEST_SUBREPO":         "two",
				"TEST_RUNTIME_SUBREPO": "runtime",
				"SOMETHING_ELSE":       "something/else",
			},
			expected: []string{"gcr.io/gauntlet/test/one", "gcr.io/gauntlet/test/two:latest", "gcr.io/gauntlet/test/runtime", "gcr.io/someorg/someimage"},
		},
		{
			name: "from-stage-ignored",
			fileContents: `
FROM gcr.io/someorg/sometool:sometag AS tools_image
FROM gcr.io/someorg/someimage AS base_image
FROM base_image
COPY --from=tools_image /bin/sometool
CMD bin`,
			expected: []string{"gcr.io/someorg/sometool:sometag", "gcr.io/someorg/someimage"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				os.Setenv(k, v)
				defer os.Unsetenv(k)
			}
			fc := newFinderCache()
			ctx := context.Background()
			got, err := fc.getImagesFromDockerfile(ctx, strings.NewReader(tc.fileContents))
			if err != nil {
				t.Fatalf("getImagesFromDockerfile returned error: %v", err)
			}
			if !reflect.DeepEqual(tc.expected, got) {
				t.Errorf("getImagesFromDockerfile returned %v, wanted %v", got, tc.expected)
			}
		})
	}
}
