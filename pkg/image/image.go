// Copyright 2021 The Sigstore Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package image

import (
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/sigstore/cosign/pkg/cosign"

	oremote "github.com/sigstore/cosign/internal/oci/remote"
)

func TargetRepositoryForImage(img name.Reference) (name.Repository, error) {
	wantRepo := os.Getenv(oremote.RepoOverrideKey)
	if wantRepo == "" {
		return img.Context(), nil
	}
	return name.NewRepository(wantRepo)
}

func AttachedImageTag(ref name.Reference, suffix string, remoteOpts ...remote.Option) (name.Tag, error) {
	h, err := Digest(ref, remoteOpts...)
	if err != nil {
		return name.Tag{}, err
	}

	repo, err := TargetRepositoryForImage(ref)
	if err != nil {
		return name.Tag{}, err
	}
	return cosign.AttachedImageTag(repo, h, suffix), nil
}

// Digest returns the digest of the image at the reference.
//
// If the reference is by digest already, it simply extracts the digest.
// Otherwise, it looks up the digest from the registry.
func Digest(ref name.Reference, remoteOpts ...remote.Option) (v1.Hash, error) {
	if d, ok := ref.(name.Digest); ok {
		return v1.NewHash(d.DigestStr())
	}
	desc, err := remote.Get(ref, remoteOpts...)
	if err != nil {
		return v1.Hash{}, err
	}
	return desc.Digest, nil
}
