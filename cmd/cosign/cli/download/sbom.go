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

	idx, ok := se.(oci.SignedImageIndex)

	if dnOpts.Platform != "" && ok {
		targetPlatform, err := v1.ParsePlatform(dnOpts.Platform)
		if err != nil {
			return nil, fmt.Errorf("parsing platform: %w", err)
		}
		im, err := idx.IndexManifest()
		if err != nil {
			return nil, fmt.Errorf("fetching index manifest: %w", err)
		}
		targetDigest := ""
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

		platforms = matchPlatform(targetPlatform, platforms)
		if len(platforms) == 0 {
			return nil, fmt.Errorf("unable to find an SBOM for %s", targetPlatform.String())
		}
		if len(platforms) > 1 {
			return nil, fmt.Errorf(
				"platform spec matches more than one image architecture: %s",
				func(pl platformList) string {
					r := []string{}
					for _, p := range pl {
						r = append(r, p.platform.String())
					}
					return strings.Join(r, ", ")
				}(platforms),
			)
		}

		nse, err := findSignedImage(ctx, idx, platforms[0].hash)
		if err != nil {
			return nil, fmt.Errorf("searching for %s image: %w", targetDigest, err)
		}
		if nse == nil {
			return nil, fmt.Errorf("unable to find image %s", targetDigest)
		}
		se = nse
	}

	// TODO: What happens if the index does not have an sbom but the images do?

	file, err := se.Attachment("sbom")
	if err != nil {
		if errors.Is(err, ociremote.ErrImageNotFound) {
			return nil, errors.New("no sbom attached to reference")
		}
		return nil, fmt.Errorf("getting sbom attachment: %+w", err)
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

// matchPlatform filters a list of platforms returning only those matching
// a base. "Based" on ko's internal equivalent while it moves to GGCR.
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
		return nil, fmt.Errorf("traversing signed entity: %+w", err)
	}
	return se, nil
}
