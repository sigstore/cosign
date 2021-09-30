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
	"fmt"
	"os"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	cremote "github.com/sigstore/cosign/pkg/cosign/remote"
)

func BlobCmd(ctx context.Context, regOpts options.RegistryOptions, files []cremote.File, contentType, imageRef string) error {
	// TODO: use contentType.
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
