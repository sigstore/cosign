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

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/pkg/oci"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	"github.com/sigstore/cosign/pkg/oci/walk"
)

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
		im, err := idx.IndexManifest()
		if err != nil {
			return nil, fmt.Errorf("fetching index manifest: %w", err)
		}
		targetDigest := ""
		for _, m := range im.Manifests {
			if m.Platform.String() == dnOpts.Platform {
				targetDigest = m.Digest.String()
				break
			}
		}
		if targetDigest != "" {
			nse, err := findSignedImage(ctx, idx, targetDigest)
			if err != nil {
				return nil, fmt.Errorf("searching for image %s: %w", targetDigest, err)
			}
			if nse == nil {
				return nil, fmt.Errorf("unable to find image %s", targetDigest)
			}
			se = nse
		}
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

func findSignedImage(ctx context.Context, sii oci.SignedImageIndex, targetDigest string) (se oci.SignedEntity, err error) {
	if err := walk.SignedEntity(ctx, sii, func(ctx context.Context, e oci.SignedEntity) error {
		img, ok := e.(oci.SignedImage)
		if !ok {
			return nil
		}

		d, err := img.Digest()
		if err != nil {
			return fmt.Errorf("getting image digest: %w", err)
		}

		if d.String() == targetDigest {
			se = img
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("traversing signed entity: %+w", err)
	}
	return se, nil
}
