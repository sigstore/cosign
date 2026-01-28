//
// Copyright 2023 The Sigstore Authors.
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

package remote

import (
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v3/pkg/cosign/bundle"
)

// Referrers fetches references using registry options.
func Referrers(d name.Digest, artifactType string, opts ...Option) (*v1.IndexManifest, error) {
	o := makeOptions(name.Repository{}, opts...)
	rOpt := o.ROpt
	if artifactType != "" {
		rOpt = append(rOpt, remote.WithFilter("artifactType", artifactType))
	}
	idx, err := remote.Referrers(d, rOpt...)
	if err != nil {
		return nil, err
	}
	return idx.IndexManifest()
}

func BundlesReferrers(d name.Digest, remoteOpts []remote.Option, opts []Option) ([]string, error) {
	var refs []string

	idxManifest, err := Referrers(d, "", opts...)
	if err != nil {
		return refs, err
	}
	if idxManifest == nil {
		return refs, nil
	}

	for _, manifest := range idxManifest.Manifests {
		layerDigestStr := fmt.Sprintf("%s@%s", d.Context().Name(), manifest.Digest.String())
		layerDigest, err := name.NewDigest(layerDigestStr)
		if err != nil {
			return refs, err
		}
		layerImage, err := remote.Image(layerDigest, remoteOpts...)
		if err != nil {
			return refs, err
		}
		layerManifest, err := layerImage.Manifest()
		if err != nil {
			return refs, err
		}
		if layerManifest != nil {
			if layerManifest.Config.ArtifactType == bundle.BundleV03MediaType {
				refs = append(refs, layerDigestStr)
			}
		}
	}

	return refs, nil
}
