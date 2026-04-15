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
	"encoding/json"
	"fmt"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/sigstore/cosign/v3/pkg/oci"
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
		return fmt.Errorf("appending signed image: %w", err)
	}
	return writeSignedEntity(layoutPath, si)
}

// WriteSignedImageIndex writes the image index and all related signatures, attestations and attachments
func WriteSignedImageIndex(path string, si oci.SignedImageIndex) error {
	// First, write an empty index
	layoutPath, err := layout.Write(path, empty.Index)
	if err != nil {
		return err
	}
	// write the image index
	if err := layoutPath.AppendIndex(si, layout.WithAnnotations(
		map[string]string{kindAnnotation: imageIndexAnnotation},
	)); err != nil {
		return fmt.Errorf("appending signed image index: %w", err)
	}
	return writeSignedEntity(layoutPath, si)
}

func writeSignedEntity(path layout.Path, se oci.SignedEntity) error {
	// write the signatures
	sigs, err := se.Signatures()
	if err != nil {
		return fmt.Errorf("getting signatures: %w", err)
	}
	if !isEmpty(sigs) {
		if err := appendImage(path, sigs, sigsAnnotation); err != nil {
			return fmt.Errorf("appending signatures: %w", err)
		}
	}

	// write attestations
	atts, err := se.Attestations()
	if err != nil {
		return fmt.Errorf("getting atts")
	}
	if !isEmpty(atts) {
		if err := appendImage(path, atts, attsAnnotation); err != nil {
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

func appendImage(path layout.Path, img v1.Image, annotation string) error {
	if err := path.WriteImage(img); err != nil {
		return err
	}
	desc, err := partial.Descriptor(img)
	if err != nil {
		return err
	}
	// partial.Descriptor falls back to config.mediaType for the ArtifactType
	// field because go-containerregistry's v1.Manifest struct does not expose
	// the OCI manifest-level artifactType. Parse the raw manifest to read it
	// directly so OCI artifacts with an explicit artifactType are saved correctly.
	if raw, rawErr := img.RawManifest(); rawErr == nil {
		var ociArtifact struct {
			ArtifactType string `json:"artifactType,omitempty"`
		}
		if json.Unmarshal(raw, &ociArtifact) == nil && ociArtifact.ArtifactType != "" {
			desc.ArtifactType = ociArtifact.ArtifactType
		}
	}
	desc.Annotations = map[string]string{kindAnnotation: annotation}
	return path.AppendDescriptor(*desc)
}
