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
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
)

// CopyCmd implements the logic to copy the supplied container image and signatures.
// nolint
func CopyCmd(ctx context.Context, regOpts options.RegistryOptions, srcImg, dstImg string, sigOnly, force bool) error {
	srcRef, err := name.ParseReference(srcImg)
	if err != nil {
		return err
	}
	dstRef, err := name.ParseReference(dstImg)
	if err != nil {
		return err
	}

	remoteOpts := regOpts.GetRegistryClientOpts(ctx)
	sigSrcRef, err := ociremote.SignatureTag(srcRef, ociremote.WithRemoteOptions(remoteOpts...))
	if err != nil {
		return err
	}

	dstRepoRef := dstRef.Context()
	sigDstRef := dstRepoRef.Tag(sigSrcRef.Identifier())
	if err := copyImage(sigSrcRef, sigDstRef, force, remoteOpts...); err != nil {
		return err
	}

	if !sigOnly {
		return copyImage(srcRef, dstRef, force, remoteOpts...)
	}

	return nil
}

func descriptorsEqual(a, b *v1.Descriptor) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Digest == b.Digest
}

func copyImage(src, dest name.Reference, overwrite bool, opts ...remote.Option) error {
	got, err := remote.Get(src, opts...)
	if err != nil {
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
