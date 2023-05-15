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
	"encoding/json"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/oci"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
)

func AttestationCmd(ctx context.Context, regOpts options.RegistryOptions, attOptions options.AttestationDownloadOptions, imageRef string) error {
	ref, err := name.ParseReference(imageRef, regOpts.NameOptions()...)
	if err != nil {
		return err
	}
	ociremoteOpts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		return err
	}

	var predicateType string
	if attOptions.PredicateType != "" {
		predicateType, err = options.ParsePredicateType(attOptions.PredicateType)
		if err != nil {
			return err
		}
	}

	se, err := ociremote.SignedEntity(ref, ociremoteOpts...)
	if err != nil {
		return err
	}

	idx, isIndex := se.(oci.SignedImageIndex)

	// We only allow --platform on multiarch indexes
	if attOptions.Platform != "" && !isIndex {
		return fmt.Errorf("specified reference is not a multiarch image")
	}

	if attOptions.Platform != "" && isIndex {
		targetPlatform, err := v1.ParsePlatform(attOptions.Platform)
		if err != nil {
			return fmt.Errorf("parsing platform: %w", err)
		}
		platforms, err := getIndexPlatforms(idx)
		if err != nil {
			return fmt.Errorf("getting available platforms: %w", err)
		}

		platforms = matchPlatform(targetPlatform, platforms)
		if len(platforms) == 0 {
			return fmt.Errorf("unable to find an SBOM for %s", targetPlatform.String())
		}
		if len(platforms) > 1 {
			return fmt.Errorf(
				"platform spec matches more than one image architecture: %s",
				platforms.String(),
			)
		}

		nse, err := idx.SignedImage(platforms[0].hash)
		if err != nil {
			return fmt.Errorf("searching for %s image: %w", platforms[0].hash.String(), err)
		}
		if nse == nil {
			return fmt.Errorf("unable to find image %s", platforms[0].hash.String())
		}
		se = nse
	}

	attestations, err := cosign.FetchAttestations(se, predicateType)
	if err != nil {
		return err
	}

	for _, att := range attestations {
		b, err := json.Marshal(att)
		if err != nil {
			return err
		}
		fmt.Println(string(b))
	}
	return nil
}
