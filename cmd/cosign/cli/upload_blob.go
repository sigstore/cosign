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

package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/peterbourgon/ff/v3/ffcli"
	cremote "github.com/sigstore/cosign/pkg/cosign/remote"
)

func fileFromFlag(s string) cremote.File {
	split := strings.Split(s, ":")
	f := cremote.File{
		Path: split[0],
	}
	if len(split) > 1 {
		split = strings.Split(split[1], "/")
		f.Platform = &v1.Platform{
			OS: split[0],
		}
		if len(split) > 1 {
			f.Platform.Architecture = split[1]
		}
	}
	return f
}

type Files struct {
	Files []cremote.File
}

func (fs *Files) Set(k string) error {
	f := fileFromFlag(k)
	fs.Files = append(fs.Files, f)

	// If we have multiple files, each file must have a platform.
	if len(fs.Files) > 1 {
		for _, f := range fs.Files {
			if f.Platform == nil {
				return fmt.Errorf("each file must include a unique platform, %s had no platform", f.Path)
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

func UploadBlob() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign upload-blob", flag.ExitOnError)
		ct      = flagset.String("ct", "", "content type to set")
	)
	fmap := Files{}
	flagset.Var(&fmap, "f", "<filepath>:[platform/arch]")
	return &ffcli.Command{
		Name:       "upload-blob",
		ShortUsage: "cosign upload-blob -f <blob ref> <image uri>",
		ShortHelp:  "Upload one or more blobs to the supplied container image address",
		LongHelp: `Upload one or more blobs to the supplied container image address.

EXAMPLES
  # upload a blob named foo to the location specified by <IMAGE>
  cosign upload-blob -f foo <IMAGE>

  # upload a blob named foo to the location specified by <IMAGE>, setting the os field to "MYOS".
  cosign upload-blob -f foo:MYOS <IMAGE>

  # upload a blob named foo to the location specified by <IMAGE>, setting the os field to "MYOS" and the platform field to "MYPLATFORM".
  cosign upload-blob -f foo:MYOS/MYPLATFORM <IMAGE>

  # upload two blobs named foo-darwin and foo-linux to the location specified by <IMAGE>, setting the os fields
  cosign upload-blob -f foo-darwin:darwin -f foo-linux:linux <IMAGE>
  `,
		FlagSet: flagset,
		Exec: func(ctx context.Context, args []string) error {
			if len(args) != 1 {
				return flag.ErrHelp
			}

			return UploadBlobCmd(ctx, fmap.Files, *ct, args[0])
		},
	}
}

func UploadBlobCmd(ctx context.Context, files []cremote.File, contentType, imageRef string) error {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return err
	}

	dgster, err := cremote.UploadFiles(ref, files)
	if err != nil {
		return err
	}
	dgst, err := dgster.Digest()
	if err != nil {
		return err
	}
	dgstAddr := fmt.Sprintf("%s@%s", ref.Context().Name(), dgst.String())

	if len(files) > 1 {
		fmt.Fprintf(os.Stderr, "Uploading multi-platform index to %s\n", dgstAddr)
	} else {
		fmt.Fprintln(os.Stderr, "Uploaded image to:")
		fmt.Println(dgstAddr)
	}
	return nil
}
