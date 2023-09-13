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
	"fmt"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/sigstore/cosign/v2/pkg/oci"
)

// WriteSignedImage writes the image and all related signatures, attestations and attachments
func WriteSignedImage(path string, si oci.SignedImage, ref name.Reference) error {
	layoutPath, err := layout.FromPath(path)
    if err != nil {
        if os.IsNotExist(err) {
            // If the layout doesn't exist, create a new one
            layoutPath, err = layout.Write(path, empty.Index)
            if err != nil {
                return err
            }
        } else {
            return err
        }
    }
	
	// write the image
	if err := appendImage(layoutPath, si, ref, ImageAnnotation); err != nil {
		return fmt.Errorf("appending signed image: %w", err)
	}
	return writeSignedEntity(layoutPath, si, ref)
}

// WriteSignedImageIndex writes the image index and all related signatures, attestations and attachments
func WriteSignedImageIndex(path string, si oci.SignedImageIndex, ref name.Reference) error {
	layoutPath, err := layout.FromPath(path)
    if err != nil {
        if os.IsNotExist(err) {
            // If the layout doesn't exist, create a new one
            layoutPath, err = layout.Write(path, empty.Index)
            if err != nil {
                return err
            }
        } else {
            return err
        }
    }

    // Append the image index
    if err := layoutPath.AppendIndex(si, layout.WithAnnotations(
        map[string]string{KindAnnotation: ImageIndexAnnotation, ImageTitleAnnotation: getImageRef(ref)},
    )); err != nil {
        return fmt.Errorf("appending signed image index: %w", err)
    }

    return writeSignedEntity(layoutPath, si, ref)
}

func writeSignedEntity(path layout.Path, se oci.SignedEntity, ref name.Reference) error {
	// write the signatures
	sigs, err := se.Signatures()
	if err != nil {
		return fmt.Errorf("getting signatures: %w", err)
	}
	if !isEmpty(sigs) {
		if err := appendImage(path, sigs, ref, SigsAnnotation); err != nil {
			return fmt.Errorf("appending signatures: %w", err)
		}
	}

	// write attestations
	atts, err := se.Attestations()
	if err != nil {
		return fmt.Errorf("getting atts")
	}
	if !isEmpty(atts) {
		if err := appendImage(path, atts, ref, AttsAnnotation); err != nil {
			return fmt.Errorf("appending atts: %w", err)
		}
	}
	// TODO (priyawadhwa@) and attachments
	return nil
}

// isEmpty returns true if the signatures or attestations are empty
func isEmpty(s oci.Signatures) bool {
	ss, _ := s.Get()
	return ss == nil
}

func appendImage(path layout.Path, img v1.Image, ref name.Reference, annotation string) error {
	return path.AppendImage(img, layout.WithAnnotations(
        map[string]string{KindAnnotation: annotation, ImageTitleAnnotation: getImageRef(ref)},
    ))
}

func getImageRef(ref name.Reference) string {
	registry := ref.Context().RegistryStr() + "/"
	imageRef := ref.Name()
	if strings.HasPrefix(imageRef, registry) {
		imageRef = imageRef[len(registry):]
	}
	return imageRef
}