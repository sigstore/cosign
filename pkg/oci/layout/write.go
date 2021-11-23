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
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/pkg/oci"
)

// WriteSignedImage writes the image and all related signatures, attestations and attachments
func WriteSignedImage(path string, si oci.SignedImage) error {
	// First, write an empty index
	layoutPath, err := layout.Write(path, empty.Index)
	if err != nil {
		return err
	}
	// write the image
	if err := appendImage(layoutPath, si, imageAnnotation); err != nil {
		return errors.Wrap(err, "appending signed image")
	}
	// write the signatures
	sigs, err := si.Signatures()
	if err != nil {
		return errors.Wrap(err, "getting signatures")
	}
	if !isEmpty(sigs) {
		if err := appendImage(layoutPath, sigs, sigsAnnotation); err != nil {
			return errors.Wrap(err, "appending signatures")
		}
	}

	// write attestations
	atts, err := si.Attestations()
	if err != nil {
		return errors.Wrap(err, "getting atts")
	}
	if !isEmpty(atts) {
		if err := appendImage(layoutPath, atts, attsAnnotation); err != nil {
			return errors.Wrap(err, "appending atts")
		}
	}
	// TODO (priyawadhwa@) and attachments
	return nil
}

// isEmpty returns true if the signatures or attesations are empty
func isEmpty(s oci.Signatures) bool {
	ss, _ := s.Get()
	return ss == nil
}

func appendImage(path layout.Path, img v1.Image, annotation string) error {
	return path.AppendImage(img, layout.WithAnnotations(
		map[string]string{kindAnnotation: annotation},
	))
}
