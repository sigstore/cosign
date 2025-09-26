// Copyright 2023 the Sigstore Authors.
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

package platform

import (
	"fmt"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sigstore/cosign/v3/pkg/oci"
)

type List []struct {
	Hash     v1.Hash
	Platform *v1.Platform
}

func (pl *List) String() string {
	r := []string{}
	for _, p := range *pl {
		r = append(r, p.Platform.String())
	}
	return strings.Join(r, ", ")
}

func GetIndexPlatforms(idx oci.SignedImageIndex) (List, error) {
	im, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("fetching index manifest: %w", err)
	}

	platforms := List{}
	for _, m := range im.Manifests {
		if m.Platform == nil {
			continue
		}
		platforms = append(platforms, struct {
			Hash     v1.Hash
			Platform *v1.Platform
		}{m.Digest, m.Platform})
	}
	return platforms, nil
}

// matchPlatform filters a list of platforms returning only those matching
// a base. "Based" on ko's internal equivalent while it moves to GGCR.
// https://github.com/google/ko/blob/e6a7a37e26d82a8b2bb6df991c5a6cf6b2728794/pkg/build/gobuild.go#L1020
func matchPlatform(base *v1.Platform, list List) List {
	ret := List{}
	for _, p := range list {
		if base.OS != "" && base.OS != p.Platform.OS {
			continue
		}
		if base.Architecture != "" && base.Architecture != p.Platform.Architecture {
			continue
		}
		if base.Variant != "" && base.Variant != p.Platform.Variant {
			continue
		}

		if base.OSVersion != "" && p.Platform.OSVersion != base.OSVersion {
			if base.OS != "windows" {
				continue
			} else { //nolint: revive
				if pcount, bcount := strings.Count(base.OSVersion, "."), strings.Count(p.Platform.OSVersion, "."); pcount == 2 && bcount == 3 {
					if base.OSVersion != p.Platform.OSVersion[:strings.LastIndex(p.Platform.OSVersion, ".")] {
						continue
					}
				} else {
					continue
				}
			}
		}
		ret = append(ret, p)
	}

	return ret
}

func SignedEntityForPlatform(se oci.SignedEntity, platform string) (oci.SignedEntity, error) {
	if platform == "" {
		// Copy all platforms
		return se, nil
	}
	idx, isIndex := se.(oci.SignedImageIndex)

	// We only allow --platform on multiarch indexes
	if !isIndex {
		return nil, fmt.Errorf("specified reference is not a multiarch image")
	}

	targetPlatform, err := v1.ParsePlatform(platform)
	if err != nil {
		return nil, fmt.Errorf("parsing platform: %w", err)
	}
	platforms, err := GetIndexPlatforms(idx)
	if err != nil {
		return nil, fmt.Errorf("getting available platforms: %w", err)
	}

	platforms = matchPlatform(targetPlatform, platforms)
	if len(platforms) == 0 {
		return nil, fmt.Errorf("unable to find an entity for %s", targetPlatform.String())
	}
	if len(platforms) > 1 {
		return nil, fmt.Errorf(
			"platform spec matches more than one image architecture: %s",
			platforms.String(),
		)
	}

	nse, err := idx.SignedImage(platforms[0].Hash)
	if err != nil {
		return nil, fmt.Errorf("searching for %s image: %w", platforms[0].Hash.String(), err)
	}
	if nse == nil {
		return nil, fmt.Errorf("unable to find image %s", platforms[0].Hash.String())
	}

	return nse, nil
}
