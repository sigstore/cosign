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
	"fmt"
	"io"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
)

func SBOMCmd(ctx context.Context, regOpts options.RegistryOptions, imageRef string, out io.Writer) ([]string, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, err
	}

	ociremoteOpts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		return nil, err
	}
	ociremoteOpts = append(ociremoteOpts,
		// TODO(mattmoor): This isn't really "signatures", consider shifting to
		// an SBOMs accessor?
		ociremote.WithSignatureSuffix(ociremote.SBOMTagSuffix))

	se, err := ociremote.SignedEntity(ref, ociremoteOpts...)
	if err != nil {
		return nil, err
	}

	// TODO(mattmoor): This logic does a shallow walk, we should use `mutate.Map`
	// if we want to collect all of the SBOMs attached at any level of an index.
	img, err := se.Signatures()
	if err != nil {
		return nil, err
	}
	sigs, err := img.Get()
	if err != nil {
		return nil, err
	}
	if len(sigs) == 0 {
		return nil, fmt.Errorf("no signatures associated with %v", ref)
	}

	sboms := make([]string, 0, len(sigs))
	for _, l := range sigs {
		mt, err := l.MediaType()
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(os.Stderr, "Found SBOM of media type: %s\n", mt)
		sbom, err := l.Payload()
		if err != nil {
			return nil, err
		}
		sboms = append(sboms, string(sbom))
		fmt.Fprintln(out, string(sbom))
	}
	return sboms, nil
}
