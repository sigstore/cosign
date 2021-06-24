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

	"github.com/google/go-containerregistry/pkg/name"
)

func TestSignatureRepositoryForImage(t *testing.T) {
	tests := []struct {
		desc    string
		image   name.Reference
		envRepo string

		want name.Repository
	}{
		{
			desc:  "no replacement",
			image: name.MustParseReference("gcr.io/test/image"),
			want:  name.MustParseReference("gcr.io/test/image").Context(),
		},
		{
			desc:    "replace repo",
			image:   name.MustParseReference("gcr.io/test/image"),
			envRepo: "gcr.io/substituted/repo",
			want:    name.MustParseReference("gcr.io/substituted/repo").Context(),
		},
		{
			desc:    "replace non-gcr repo",
			image:   name.MustParseReference("test/image"),
			envRepo: "newrepo",
			want:    name.MustParseReference("index.docker.io/library/newrepo").Context(),
		},
		{
			desc:    "replace tag",
			image:   name.MustParseReference("gcr.io/test/image:test-tag"),
			envRepo: "gcr.io/substituted/repo",
			want:    name.MustParseReference("gcr.io/substituted/repo").Context(),
		},
		{
			desc:    "replace digest",
			image:   name.MustParseReference("gcr.io/test/image@sha256:0fdb560330001172f590ec91daa5a92d76b31ec591525360203992ef27fa2a56"),
			envRepo: "gcr.io/substituted/repo",
			want:    name.MustParseReference("gcr.io/substituted/repo").Context(),
		},
		{
			desc:    "ecr test",
			image:   name.MustParseReference("myaccount.dkr.ecr.us-west-2.amazonaws.com/repo1:tag"),
			envRepo: "myaccount.dkr.ecr.us-west-2.amazonaws.com/repo2",
			want:    name.MustParseReference("myaccount.dkr.ecr.us-west-2.amazonaws.com/repo2").Context(),
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			os.Setenv(repoEnv, test.envRepo)
			defer os.Unsetenv(repoEnv)

			got, err := SignatureRepositoryForImage(test.image)
			if err != nil {
				t.Fatalf("SignatureRepositoryForImage returned error: %v", err)
			}
			if got.Name() != test.want.Name() {
				t.Errorf("expected %s got %s", test.want, got.Name())
			}
		})
	}
}
