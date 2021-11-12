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

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/pkg/oci"
)

// WriteSignedImage writes the image and all related signatures, attestations and attachments
func WriteSignedImage(path string, si oci.SignedImage) error {
	// First, write the image
	if err := write(path, imagePath, si); err != nil {
		return errors.Wrap(err, "writing image")
	}
	sigs, err := si.Signatures()
	if err != nil {
		return errors.Wrap(err, "getting signatures")
	}
	if err := write(path, signaturesPath, sigs); err != nil {
		return errors.Wrap(err, "writing signatures")
	}
	// TODO (priyawadhwa@) write attestations and attachments
	return nil
}

func imagePath(path string) string {
	return filepath.Join(path, "image")
}

func signaturesPath(path string) string {
	return filepath.Join(path, "sigs")
}

type pathFunc func(string) string

func write(path string, pf pathFunc, img v1.Image) error {
	p := pf(path)
	// write empty image
	layoutPath, err := layout.Write(p, empty.Index)
	if err != nil {
		return err
	}
	// write image to disk
	return layoutPath.AppendImage(img)
}
