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
	"runtime"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/common"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/pkg/oci"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/cosign/v2/pkg/oci/walk"
	"golang.org/x/sync/errgroup"
)

// CopyCmd implements the logic to copy the supplied container image and signatures.
// nolint
func CopyCmd(ctx context.Context, regOpts options.RegistryOptions, srcImg, dstImg string, sigOnly, force bool, platform string) error {
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

	ociRemoteOpts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		return err
	}

	remoteOpts := regOpts.GetRegistryClientOpts(ctx)

	pusher, err := remote.NewPusher(remoteOpts...)
	if err != nil {
		return err
	}

	ociRemoteOpts = append(ociRemoteOpts, ociremote.WithRemoteOptions(remoteOpts...))

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(runtime.GOMAXPROCS(0))

	root, err := ociremote.SignedEntity(srcRef, ociRemoteOpts...)
	if err != nil {
		return err
	}

	idx, isIndex := root.(oci.SignedImageIndex)

	if platform != "" && !isIndex {
		return fmt.Errorf("specified reference is not a multiarch image")
	}

	if platform != "" && isIndex {
		targetPlatform, err := v1.ParsePlatform(platform)
		if err != nil {
			return fmt.Errorf("parsing platform: %w", err)
		}
		platforms, err := common.GetIndexPlatforms(idx)
		if err != nil {
			return fmt.Errorf("getting available platforms: %w", err)
		}

		platforms = common.MatchPlatform(targetPlatform, platforms)
		if len(platforms) == 0 {
			return fmt.Errorf("unable to find an SBOM for %s", targetPlatform.String())
		}
		if len(platforms) > 1 {
			return fmt.Errorf(
				"platform spec matches more than one image architecture: %s",
				platforms.String(),
			)
		}

		nroot, err := idx.SignedImage(platforms[0].Hash)
		if err != nil {
			return fmt.Errorf("searching for %s image: %w", platforms[0].Hash.String(), err)
		}
		if nroot == nil {
			return fmt.Errorf("unable to find image %s", platforms[0].Hash.String())
		}
		root = nroot
	}

	if err := walk.SignedEntity(gctx, root, func(ctx context.Context, se oci.SignedEntity) error {
		// Both of the SignedEntity types implement Digest()
		h, err := se.Digest()
		if err != nil {
			return err
		}
		srcDigest := srcRepoRef.Digest(h.String())

		copyTag := func(tm tagMap) error {
			src, err := tm(srcDigest, ociRemoteOpts...)
			if err != nil {
				return err
			}

			dst := dstRepoRef.Tag(src.Identifier())
			g.Go(func() error {
				return remoteCopy(ctx, pusher, src, dst, force, remoteOpts...)
			})

			return nil
		}

		if err := copyTag(ociremote.SignatureTag); err != nil {
			return err
		}

		if sigOnly {
			return nil
		}

		for _, tm := range []tagMap{ociremote.AttestationTag, ociremote.SBOMTag} {
			if err := copyTag(tm); err != nil {
				return err
			}
		}

		// Copy the entity itself.
		g.Go(func() error {
			dst := dstRepoRef.Tag(srcDigest.Identifier())
			dst = dst.Tag(fmt.Sprint(regOpts.RefOpts.TagPrefix, h.Algorithm, "-", h.Hex))
			return remoteCopy(ctx, pusher, srcDigest, dst, force, remoteOpts...)
		})

		return nil
	}); err != nil {
		return err
	}

	// Wait for everything to be copied over.
	if err := g.Wait(); err != nil {
		return err
	}

	// If we're only copying sigs, we have nothing left to do.
	if sigOnly {
		return nil
	}

	// Now that everything has been copied over, update the tag.
	h, err := root.Digest()
	if err != nil {
		return err
	}
	return remoteCopy(ctx, pusher, srcRepoRef.Digest(h.String()), dstRef, force, remoteOpts...)
}

func descriptorsEqual(a, b *v1.Descriptor) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Digest == b.Digest
}

type tagMap func(name.Reference, ...ociremote.Option) (name.Tag, error)

func remoteCopy(ctx context.Context, pusher *remote.Pusher, src, dest name.Reference, overwrite bool, opts ...remote.Option) error {
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
	return pusher.Push(ctx, dest, got)
}
