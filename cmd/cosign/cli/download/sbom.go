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

package download

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/pkg/oci"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	"github.com/sigstore/cosign/pkg/oci/walk"
)

type platformList []struct {
	hash     v1.Hash
	platform *v1.Platform
}

func (pl *platformList) String() string {
	r := []string{}
	for _, p := range *pl {
		r = append(r, p.platform.String())
	}
	return strings.Join(r, ", ")
}

func SBOMCmd(
	ctx context.Context, regOpts options.RegistryOptions,
	dnOpts options.SBOMDownloadOptions, imageRef string, out io.Writer,
) ([]string, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, err
	}

	ociremoteOpts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		return nil, err
	}

	se, err := ociremote.SignedEntity(ref, ociremoteOpts...)
	if err != nil {
		return nil, err
	}

	idx, isIndex := se.(oci.SignedImageIndex)

	// We only allow --platform on multiarch indexes
	if dnOpts.Platform != "" && !isIndex {
		return nil, fmt.Errorf("specified reference is not a multiarch image")
	}

	if dnOpts.Platform != "" && isIndex {
		targetPlatform, err := v1.ParsePlatform(dnOpts.Platform)
		if err != nil {
			return nil, fmt.Errorf("parsing platform: %w", err)
		}
		platforms, err := getIndexPlatforms(idx)
		if err != nil {
			return nil, fmt.Errorf("getting available platforms: %w", err)
		}

		platforms = matchPlatform(targetPlatform, platforms)
		if len(platforms) == 0 {
			return nil, fmt.Errorf("unable to find an SBOM for %s", targetPlatform.String())
		}
		if len(platforms) > 1 {
			return nil, fmt.Errorf(
				"platform spec matches more than one image architecture: %s",
				platforms.String(),
			)
		}

		nse, err := findSignedImage(ctx, idx, platforms[0].hash)
		if err != nil {
			return nil, fmt.Errorf("searching for %s image: %w", platforms[0].hash.String(), err)
		}
		if nse == nil {
			return nil, fmt.Errorf("unable to find image %s", platforms[0].hash.String())
		}
		se = nse
	}

	file, err := se.Attachment("sbom")
	if errors.Is(err, ociremote.ErrImageNotFound) {
		if !isIndex {
			return nil, errors.New("no sbom attached to reference")
		}
		// Help the user with the available architectures
		pl, err := getIndexPlatforms(idx)
		if len(pl) > 0 && err == nil {
			fmt.Fprintf(
				os.Stderr,
				"\nThis multiarch image does not have an SBOM attached at the index level.\n"+
					"Try using --platform with one of the following architectures:\n%s\n\n",
				pl.String(),
			)
		}
		return nil, fmt.Errorf("no SBOM found attached to image index")
	} else if err != nil {
		return nil, fmt.Errorf("getting sbom attachment: %w", err)
	}

	// "attach sbom" attaches a single static.NewFile
	sboms := make([]string, 0, 1)

	mt, err := file.FileMediaType()
	if err != nil {
		return nil, err
	}

	fmt.Fprintf(os.Stderr, "Found SBOM of media type: %s\n", mt)
	sbom, err := file.Payload()
	if err != nil {
		return nil, err
	}

	sboms = append(sboms, string(sbom))
	fmt.Fprint(out, string(sbom))

	return sboms, nil
}

func getIndexPlatforms(idx oci.SignedImageIndex) (platformList, error) {
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
			hash     v1.Hash
			platform *v1.Platform
		}{m.Digest, m.Platform})
	}
	return platforms, nil
}

// matchPlatform filters a list of platforms returning only those matching
// a base. "Based" on ko's internal equivalent while it moves to GGCR.
// https://github.com/google/ko/blob/e6a7a37e26d82a8b2bb6df991c5a6cf6b2728794/pkg/build/gobuild.go#L1020
func matchPlatform(base *v1.Platform, list platformList) platformList {
	ret := platformList{}
	for _, p := range list {
		if base.OS != "" && base.OS != p.platform.OS {
			continue
		}
		if base.Architecture != "" && base.Architecture != p.platform.Architecture {
			continue
		}
		if base.Variant != "" && base.Variant != p.platform.Variant {
			continue
		}

		if base.OSVersion != "" && p.platform.OSVersion != base.OSVersion {
			if base.OS != "windows" {
				continue
			} else {
				if pcount, bcount := strings.Count(base.OSVersion, "."), strings.Count(p.platform.OSVersion, "."); pcount == 2 && bcount == 3 {
					if base.OSVersion != p.platform.OSVersion[:strings.LastIndex(p.platform.OSVersion, ".")] {
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

func findSignedImage(ctx context.Context, sii oci.SignedImageIndex, iDigest v1.Hash) (se oci.SignedEntity, err error) {
	if err := walk.SignedEntity(ctx, sii, func(ctx context.Context, e oci.SignedEntity) error {
		img, ok := e.(oci.SignedImage)
		if !ok {
			return nil
		}

		d, err := img.Digest()
		if err != nil {
			return fmt.Errorf("getting image digest: %w", err)
		}

		if d == iDigest {
			se = img
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("traversing signed entity: %w", err)
	}
	return se, nil
}
