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

// Indirected for testing. These wrap the two registry-touching stages so the
// command flow (which format(s) to emit) can be exercised without a registry.
var (
	writeNewBundles      = writeNewBundlesImpl
	writeOldAttestations = writeOldAttestationsImpl
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

	// Gather any new-format (sigstore bundle) attestations. Unlike the verify
	// subcommands, download is an inspection command, so it does not
	// short-circuit here: an image can carry both new-format bundles and
	// old-format .att attestations, and download should emit both. GetBundles
	// returns every bundle referrer (including signature-only bundles), so this
	// branch may run even when there are no matching attestations.
	wrote, err := writeNewBundles(ctx, ref, ociremoteOpts, predicateType, out)
	if err != nil {
		return err
	}

	// Also gather any old-format (sha256-<digest>.att) attestations. If at
	// least one new-format bundle was already written, a missing old-format
	// entity or an image with no old-format attestations is not fatal: just
	// return what has been emitted so far. If nothing was written yet, keep the
	// original behavior and surface the error.
	if err := writeOldAttestations(ref, ociremoteOpts, attOptions.Platform, predicateType, out); err != nil {
		if wrote > 0 {
			return nil
		}
		return err
	}
	return nil
}

// writeNewBundlesImpl fetches new-format (sigstore bundle) attestation referrers
// and writes those matching predicateType to out. It returns the number written.
// A failure to look up bundles is not fatal (the image may only carry old-format
// attestations), so it returns 0 with no error in that case.
func writeNewBundlesImpl(ctx context.Context, ref name.Reference, ociremoteOpts []ociremote.Option, predicateType string, out io.Writer) (int, error) {
	newBundles, _, err := cosign.GetBundles(ctx, ref, ociremoteOpts)
	if err != nil || len(newBundles) == 0 {
		return 0, nil
	}
	wrote := 0
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
			return wrote, err
		}
		if _, err = out.Write(append(b, byte('\n'))); err != nil {
			return wrote, err
		}
		wrote++
	}
	return wrote, nil
}

// writeOldAttestationsImpl fetches old-format (sha256-<digest>.att) attestations
// for ref and writes those matching predicateType to out.
func writeOldAttestationsImpl(ref name.Reference, ociremoteOpts []ociremote.Option, plat, predicateType string, out io.Writer) error {
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

	se, err = platform.SignedEntityForPlatform(se, plat)
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
		if _, err = out.Write(append(b, byte('\n'))); err != nil {
			return err
		}
	}
	return nil
}
