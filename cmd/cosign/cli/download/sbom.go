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
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/platform"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
)

func SBOMCmd(
	ctx context.Context, regOpts options.RegistryOptions,
	dnOpts options.SBOMDownloadOptions, imageRef string, out io.Writer,
) ([]string, error) {
	ref, err := name.ParseReference(imageRef, regOpts.NameOptions()...)
	if err != nil {
		return nil, err
	}

	ociremoteOpts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		return nil, err
	}

	se, err := ociremote.SignedEntity(ref, ociremoteOpts...)
	var entityNotFoundError *ociremote.EntityNotFoundError
	if err != nil {
		if errors.As(err, &entityNotFoundError) {
			// We don't need to access the original image to download the attached sbom
			if digest, ok := ref.(name.Digest); ok {
				se = ociremote.SignedUnknown(digest)
			} else {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	se, err = platform.SignedEntityForPlatform(se, dnOpts.Platform)
	if err != nil {
		return nil, err
	}

	idx, isIndex := se.(oci.SignedImageIndex)

	file, err := se.Attachment("sbom")
	if errors.Is(err, ociremote.ErrImageNotFound) {
		if !isIndex {
			return nil, errors.New("no sbom attached to reference")
		}
		// Help the user with the available architectures
		pl, err := platform.GetIndexPlatforms(idx)
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
