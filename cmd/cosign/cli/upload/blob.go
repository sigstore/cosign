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

package upload

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/peterbourgon/ff/v3/ffcli"

	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	cremote "github.com/sigstore/cosign/pkg/cosign/remote"
)

type Files struct {
	Files []cremote.File
}

func (fs *Files) Set(k string) error {
	f := cremote.FileFromFlag(k)
	fs.Files = append(fs.Files, f)

	// If we have multiple files, each file must have a platform.
	if len(fs.Files) > 1 {
		for _, f := range fs.Files {
			if f.Platform() == nil {
				return fmt.Errorf("each file must include a unique platform, %s had no platform", f.Path())
			}
		}
	}
	return nil
}

func (fs *Files) String() string {
	s := []string{}
	for _, f := range fs.Files {
		s = append(s, f.String())
	}
	return strings.Join(s, ",")
}

func Blob() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign upload blob", flag.ExitOnError)
		ct      = flagset.String("ct", "", "content type to set")
		regOpts options.RegistryOpts
	)
	options.ApplyRegistryFlags(&regOpts, flagset)
	fmap := Files{}
	flagset.Var(&fmap, "f", "<filepath>:[platform/arch]")
	return &ffcli.Command{
		Name:       "blob",
		ShortUsage: "cosign upload blob -f <blob ref> <image uri>",
		ShortHelp:  "Upload one or more blobs to the supplied container image address",
		LongHelp: `Upload one or more blobs to the supplied container image address.

EXAMPLES
  # upload a blob named foo to the location specified by <IMAGE>
  cosign upload blob -f foo <IMAGE>

  # upload a blob named foo to the location specified by <IMAGE>, setting the os field to "MYOS".
  cosign upload blob -f foo:MYOS <IMAGE>

  # upload a blob named foo to the location specified by <IMAGE>, setting the os field to "MYOS" and the platform field to "MYPLATFORM".
  cosign upload blob -f foo:MYOS/MYPLATFORM <IMAGE>

  # upload two blobs named foo-darwin and foo-linux to the location specified by <IMAGE>, setting the os fields
  cosign upload blob -f foo-darwin:darwin -f foo-linux:linux <IMAGE>
  `,
		FlagSet: flagset,
		Exec: func(ctx context.Context, args []string) error {
			if len(args) != 1 || len(fmap.Files) < 1 {
				return flag.ErrHelp
			}

			return BlobCmd(ctx, regOpts, fmap.Files, *ct, args[0])
		},
	}
}

func BlobCmd(ctx context.Context, regOpts options.RegistryOpts, files []cremote.File, contentType, imageRef string) error {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return err
	}

	dgstAddr, err := cremote.UploadFiles(ref, files, cremote.DefaultMediaTypeGetter, regOpts.GetRegistryClientOpts(ctx)...)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return errors.New("no files uploaded?")
	}
	if len(files) > 1 {
		fmt.Fprintf(os.Stderr, "Uploading multi-platform index to %s\n", dgstAddr)
	} else {
		fmt.Fprintln(os.Stderr, "Uploaded image to:")
		fmt.Println(dgstAddr)
	}
	return nil
}
