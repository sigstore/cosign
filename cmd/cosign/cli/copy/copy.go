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

package copy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/pkg/oci"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	"github.com/sigstore/cosign/pkg/oci/walk"
)

// CopyCmd implements the logic to copy the supplied container image and signatures.
// nolint
func CopyCmd(ctx context.Context, regOpts options.RegistryOptions, srcImg, dstImg string, sigOnly, force bool) error {
	no := regOpts.NameOptions()
	srcRef, err := name.ParseReference(srcImg, no...)
	if err != nil {
		return err
	}
	srcRepoRef := srcRef.Context()

	dstRef, err := name.ParseReference(dstImg, no...)
	if err != nil {
		return err
	}
	dstRepoRef := dstRef.Context()

	remoteOpts := regOpts.GetRegistryClientOpts(ctx)
	root, err := ociremote.SignedEntity(srcRef, ociremote.WithRemoteOptions(remoteOpts...))
	if err != nil {
		return err
	}

	if err := walk.SignedEntity(ctx, root, func(ctx context.Context, se oci.SignedEntity) error {
		// Both of the SignedEntity types implement Digest()
		h, err := se.(interface{ Digest() (v1.Hash, error) }).Digest()
		if err != nil {
			return err
		}
		srcDigest := srcRepoRef.Digest(h.String())

		// Copy signatures.
		if err := copyTagImage(ociremote.SignatureTag, srcDigest, dstRepoRef, force, remoteOpts...); err != nil {
			return err
		}
		if sigOnly {
			return nil
		}

		// Copy attestations
		if err := copyTagImage(ociremote.AttestationTag, srcDigest, dstRepoRef, force, remoteOpts...); err != nil {
			return err
		}

		// Copy SBOMs
		if err := copyTagImage(ociremote.SBOMTag, srcDigest, dstRepoRef, force, remoteOpts...); err != nil {
			return err
		}

		// Copy the entity itself.
		if err := copyImage(srcDigest, dstRepoRef.Tag(srcDigest.Identifier()), force, remoteOpts...); err != nil {
			return err
		}

		return nil
	}); err != nil {
		return err
	}
	if sigOnly {
		return nil
	}

	// Now that everything has been copied over, update the tag.
	h, err := root.(interface{ Digest() (v1.Hash, error) }).Digest()
	if err != nil {
		return err
	}
	return copyImage(srcRepoRef.Digest(h.String()), dstRef, force, remoteOpts...)
}

func descriptorsEqual(a, b *v1.Descriptor) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Digest == b.Digest
}

type tagMap func(name.Reference, ...ociremote.Option) (name.Tag, error)

func copyTagImage(tm tagMap, srcDigest name.Digest, dstRepo name.Repository, overwrite bool, opts ...remote.Option) error {
	src, err := tm(srcDigest, ociremote.WithRemoteOptions(opts...))
	if err != nil {
		return err
	}
	return copyImage(src, dstRepo.Tag(src.Identifier()), overwrite, opts...)
}

func copyImage(src, dest name.Reference, overwrite bool, opts ...remote.Option) error {
	got, err := remote.Get(src, opts...)
	if err != nil {
		var te *transport.Error
		if errors.As(err, &te) && te.StatusCode == http.StatusNotFound {
			// We do not treat 404s on the source image as errors because we are
			// trying many flavors of tag (sig, sbom, att) and only a subset of
			// these are likely to exist, especially when we're talking about a
			// multi-arch image.
			return nil
		}
		return err
	}

	if !overwrite {
		if dstDesc, err := remote.Head(dest, opts...); err == nil {
			if descriptorsEqual(&got.Descriptor, dstDesc) {
				return nil
			}
			return fmt.Errorf("image %q already exists. Use `-f` to overwrite", dest.Name())
		}
	}

	fmt.Fprintf(os.Stderr, "Copying %s to %s...\n", src, dest)
	if got.MediaType.IsIndex() {
		imgIdx, err := got.ImageIndex()
		if err != nil {
			return err
		}
		return remote.WriteIndex(dest, imgIdx, opts...)
	}

	img, err := got.Image()
	if err != nil {
		return err
	}
	return remote.Write(dest, img, opts...)
}
