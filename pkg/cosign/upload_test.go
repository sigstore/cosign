/*
Copyright The Rekor Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cosign

import (
	"os"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

func TestDestinationTag(t *testing.T) {
	tests := []struct {
		desc  string
		image string
		repo  string
		want  string
	}{
		{
			desc:  "don't specify repo",
			image: "gcr.io/test/test",
			want:  "gcr.io/test/test:sha256-digest.cosign",
		}, {
			desc:  "replace repo",
			image: "gcr.io/test/image",
			repo:  "gcr.io/new",
			want:  "gcr.io/new/image:sha256-digest.cosign",
		}, {
			desc:  "image has subrepos",
			image: "gcr.io/test/image/sub",
			repo:  "gcr.io/new",
			want:  "gcr.io/new/image/sub:sha256-digest.cosign",
		}, {
			desc:  "repo has subrepos",
			image: "gcr.io/test/image/sub",
			repo:  "gcr.io/new/subrepo",
			want:  "gcr.io/new/subrepo/image/sub:sha256-digest.cosign",
		}, {
			desc:  "replace not gcr repo",
			image: "test/image",
			repo:  "newrepo",
			want:  "index.docker.io/newrepo/image:sha256-digest.cosign",
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			os.Setenv(repoEnv, test.repo)
			defer os.Unsetenv(repoEnv)

			ref, err := name.ParseReference(test.image)
			if err != nil {
				t.Fatalf("error parsing reference: %v", err)
			}
			img := &remote.Descriptor{
				Descriptor: v1.Descriptor{
					Digest: v1.Hash{
						Algorithm: "sha256",
						Hex:       "digest",
					},
				},
			}
			got, err := DestinationTag(ref, img)
			if err != nil {
				t.Fatalf("error destination tag: %v", err)
			}
			if got.Name() != test.want {
				t.Fatalf("expected %s got %s", test.want, got.Name())
			}
		})
	}
}
