package common

import (
	"fmt"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sigstore/cosign/v2/pkg/oci"
)

type platformList []struct {
	Hash     v1.Hash
	Platform *v1.Platform
}

func (pl *platformList) String() string {
	r := []string{}
	for _, p := range *pl {
		r = append(r, p.Platform.String())
	}
	return strings.Join(r, ", ")
}

func GetIndexPlatforms(idx oci.SignedImageIndex) (platformList, error) {
	im, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("fetching index manifest: %w", err)
	}

	platforms := platformList{}
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
func MatchPlatform(base *v1.Platform, list platformList) platformList {
	ret := platformList{}
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
