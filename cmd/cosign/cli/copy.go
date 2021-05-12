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

package cli

import (
	"context"
	"flag"
	"fmt"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/sigstore/cosign/pkg/cosign"
)

func Copy() *ffcli.Command {
	var (
		flagset     = flag.NewFlagSet("cosign copy", flag.ExitOnError)
		sigOnlyFlag = flagset.Bool("sig-only", false, "only copy the image signature")
		forceFlag   = flagset.Bool("f", false, "overwrite destination image(s), if necessary")
	)
	return &ffcli.Command{
		Name:       "copy",
		ShortUsage: "cosign copy <source image> <destination image>",
		ShortHelp:  `Copy the supplied container image and signatures.`,
		LongHelp: `Copy the supplied container image and signatures.

EXAMPLES
  # copy a container image and its signatures
  cosign copy example.com/src:latest example.com/dest:latest

  # copy the signatures only
  cosign copy -sig-only example.com/src example.com/dest

  # overwrite destination image and signatures
  cosign copy -f example.com/src example.com/dest
  `,
		FlagSet: flagset,
		Exec: func(ctx context.Context, args []string) error {
			if len(args) != 2 {
				return flag.ErrHelp
			}
			return CopyCmd(ctx, args[0], args[1], *sigOnlyFlag, *forceFlag)
		},
	}
}

func CopyCmd(ctx context.Context, srcImg, dstImg string, sigOnly, force bool) error {
	remoteAuth := remote.WithAuthFromKeychain(authn.DefaultKeychain)

	srcRef, err := name.ParseReference(srcImg)
	if err != nil {
		return err
	}
	dstRef, err := name.ParseReference(dstImg)
	if err != nil {
		return err
	}

	gotSrc, err := remote.Get(srcRef, remoteAuth)
	if err != nil {
		return err
	}

	sigSrcRef, err := cosign.DestinationRef(srcRef, gotSrc)
	if err != nil {
		return err
	}

	dstRepoRef := dstRef.Context()
	sigDstRef := dstRepoRef.Tag(sigSrcRef.Identifier())

	if err := copyImage(sigSrcRef, sigDstRef, force, remoteAuth); err != nil {
		return err
	}

	if !sigOnly {
		if err := copyImage(srcRef, dstRef, force, remoteAuth); err != nil {
			return err
		}
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
