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

package layout

import (
	"path/filepath"

	ociremote "github.com/sigstore/cosign/pkg/oci/remote"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/pkg/errors"
)

func WriteSignedImage(path string, ref name.Reference) error {
	// First, write the image
	if err := write(path, imagePath, ref); err != nil {
		return errors.Wrap(err, "writing image")
	}
	// Then, write the signatures
	sigRef, err := ociremote.SignatureTag(ref)
	if err != nil {
		return err
	}
	if err := write(path, signaturesPath, sigRef); err != nil {
		return errors.Wrap(err, "writing signatures")
	}
	// TODO (priyawadhwa@) write attestations and attachments
	return nil
}

func imagePath(path string) string {
	return filepath.Join(path, "image")
}

func signaturesPath(path string) string {
	return filepath.Join(path, "signatures")
}

type pathFunc func(string) string

func write(path string, pf pathFunc, ref name.Reference) error {
	p := pf(path)
	// write empty image
	layoutPath, err := layout.Write(p, empty.Index)
	if err != nil {
		return err
	}
	// get the image
	img, err := remote.Image(ref)
	if err != nil {
		return err
	}
	// write image to disk
	if err := layoutPath.AppendImage(img); err != nil {
		return err
	}
	return nil
}
