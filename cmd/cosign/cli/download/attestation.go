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
	"errors"
	"io"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/oci/platform"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
)

func AttestationCmd(ctx context.Context, regOpts options.RegistryOptions, attOptions options.AttestationDownloadOptions, imageRef string, out io.Writer) error {
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

	// Try bundles first
	newBundles, _, err := cosign.GetBundles(ctx, ref, ociremoteOpts)
	if err == nil && len(newBundles) > 0 {
		for _, eachBundle := range newBundles {
			if predicateType != "" {
				envelope, err := eachBundle.Envelope()
				if err != nil || envelope == nil {
					continue
				}
				statement, err := envelope.Statement()
				if err != nil || statement == nil {
					continue
				}
				if statement.PredicateType != predicateType {
					continue
				}
			}
			b, err := json.Marshal(eachBundle)
			if err != nil {
				return err
			}
			_, err = out.Write(append(b, byte('\n')))
			if err != nil {
				return err
			}
		}
		return nil
	}

	se, err := ociremote.SignedEntity(ref, ociremoteOpts...)
	var entityNotFoundError *ociremote.EntityNotFoundError
	if err != nil {
		if errors.As(err, &entityNotFoundError) {
			if digest, ok := ref.(name.Digest); ok {
				// We don't need to access the original image to download the attached attestation
				se = ociremote.SignedUnknown(digest)
			} else {
				return err
			}
		} else {
			return err
		}
	}

	se, err = platform.SignedEntityForPlatform(se, attOptions.Platform)
	if err != nil {
		return err
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
		_, err = out.Write(append(b, byte('\n')))
		if err != nil {
			return err
		}
	}
	return nil
}
