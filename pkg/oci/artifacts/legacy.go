//
// Copyright 2024 The Sigstore Authors.
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

package artifacts

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
)

// LegacyArtifactManager implements the ArtifactManager interface using legacy tag-based storage
type LegacyArtifactManager struct {
	opts []ociremote.Option
}

// FindArtifacts implements unified artifact discovery for legacy mode
func (m *LegacyArtifactManager) FindArtifacts(ctx context.Context, subject name.Digest, artifactType string, filters ...Filter) ([]Artifact, error) {
	switch artifactType {
	case "sig":
		signatures, err := m.FindSignatures(ctx, subject)
		if err != nil {
			return nil, err
		}
		var artifacts []Artifact
		for _, sig := range signatures {
			content, _ := json.Marshal(sig)
			artifact := Artifact{
				Type:      "sig",
				Content:   content,
				MediaType: "application/vnd.dev.cosign.simplesigning.v1+json",
				Digest:    subject,
				Metadata: map[string]interface{}{
					"signature": sig.Base64Signature,
					"payload":   sig.Payload,
					"cert":      sig.Cert,
					"chain":     sig.Chain,
					"bundle":    sig.Bundle,
				},
			}
			// Apply filters
			includeArtifact := true
			for _, filter := range filters {
				if !filter.Apply(artifact) {
					includeArtifact = false
					break
				}
			}
			if includeArtifact {
				artifacts = append(artifacts, artifact)
			}
		}
		return artifacts, nil
	case "att":
		attestations, err := m.FindAttestations(ctx, subject, "")
		if err != nil {
			return nil, err
		}
		var artifacts []Artifact
		for _, att := range attestations {
			content, _ := json.Marshal(att)
			artifact := Artifact{
				Type:      "att",
				Content:   content,
				MediaType: "application/vnd.dsse.envelope.v1+json",
				Digest:    subject,
				Metadata: map[string]interface{}{
					"payloadType": att.PayloadType,
					"payload":     att.PayLoad,
					"signatures":  att.Signatures,
				},
			}
			// Apply filters
			includeArtifact := true
			for _, filter := range filters {
				if !filter.Apply(artifact) {
					includeArtifact = false
					break
				}
			}
			if includeArtifact {
				artifacts = append(artifacts, artifact)
			}
		}
		return artifacts, nil
	case "sbom":
		sboms, err := m.FindSBOMs(ctx, subject)
		if err != nil {
			return nil, err
		}
		var artifacts []Artifact
		for _, sbom := range sboms {
			artifact := Artifact{
				Type:      "sbom",
				Content:   sbom.Content,
				MediaType: sbom.MediaType,
				Digest:    sbom.Digest,
				Metadata:  map[string]interface{}{},
			}
			// Apply filters
			includeArtifact := true
			for _, filter := range filters {
				if !filter.Apply(artifact) {
					includeArtifact = false
					break
				}
			}
			if includeArtifact {
				artifacts = append(artifacts, artifact)
			}
		}
		return artifacts, nil
	default:
		return nil, fmt.Errorf("unsupported artifact type: %s", artifactType)
	}
}

// AttachArtifact implements unified artifact attachment for legacy mode
func (m *LegacyArtifactManager) AttachArtifact(ctx context.Context, subject name.Digest, artifact Artifact, opts AttachOptions) error {
	switch artifact.Type {
	case "sig":
		var sig cosign.SignedPayload
		if err := json.Unmarshal(artifact.Content, &sig); err != nil {
			return fmt.Errorf("invalid signature artifact: %w", err)
		}
		// Convert to oci.Signature for attachment
		ociSig, err := static.NewSignature(sig.Payload, sig.Base64Signature)
		if err != nil {
			return fmt.Errorf("creating oci signature: %w", err)
		}
		return m.AttachSignature(ctx, subject, ociSig, opts)
	case "att":
		var att cosign.AttestationPayload
		if err := json.Unmarshal(artifact.Content, &att); err != nil {
			return fmt.Errorf("invalid attestation artifact: %w", err)
		}
		// Convert to oci.Signature for attachment
		ociAtt, err := static.NewAttestation([]byte(att.PayLoad))
		if err != nil {
			return fmt.Errorf("creating oci attestation: %w", err)
		}
		return m.AttachAttestation(ctx, subject, ociAtt, opts)
	case "sbom":
		mediaType := types.MediaType(artifact.MediaType)
		return m.AttachSBOM(ctx, subject, artifact.Content, mediaType, opts)
	default:
		return fmt.Errorf("unsupported artifact type for attachment: %s", artifact.Type)
	}
}

// CreateArtifact implements unified artifact creation for legacy mode
func (m *LegacyArtifactManager) CreateArtifact(ctx context.Context, subject name.Digest, content []byte, artifactType string, signingOpts SigningOptions, attachOpts AttachOptions) error {
	switch artifactType {
	case "sig":
		return m.CreateSignature(ctx, subject, content, signingOpts, attachOpts)
	case "att":
		if signingOpts.AttestSpecific == nil {
			return fmt.Errorf("attestation creation requires AttestSpecific options")
		}
		return m.CreateAttestation(ctx, subject, content, signingOpts.AttestSpecific.PredicateType, signingOpts, attachOpts)
	default:
		return fmt.Errorf("unsupported artifact type for creation: %s", artifactType)
	}
}

// FindSignatures implements legacy signature discovery
func (m *LegacyArtifactManager) FindSignatures(_ context.Context, subject name.Digest) ([]cosign.SignedPayload, error) {
	simg, err := ociremote.SignedImage(subject, m.opts...)
	if err != nil {
		// If image not found, return empty slice (no signatures exist)
		return []cosign.SignedPayload{}, nil
	}
	signatures, err := cosign.FetchSignatures(simg)
	if err != nil {
		// If no signatures found, return empty slice instead of error
		if err.Error() == "no signatures associated" {
			return []cosign.SignedPayload{}, nil
		}
		return nil, err
	}
	return signatures, nil
}

// FindAttestations implements legacy attestation discovery
func (m *LegacyArtifactManager) FindAttestations(_ context.Context, subject name.Digest, predicateType string) ([]cosign.AttestationPayload, error) {
	se, err := ociremote.SignedEntity(subject, m.opts...)
	if err != nil {
		// If entity not found, return empty slice (no attestations exist)
		return []cosign.AttestationPayload{}, nil
	}
	attestations, err := cosign.FetchAttestations(se, predicateType)
	if err != nil {
		// If no attestations found, return empty slice instead of error
		if err.Error() == "found no attestations" {
			return []cosign.AttestationPayload{}, nil
		}
		return nil, err
	}
	return attestations, nil
}

// FindSBOMs implements legacy SBOM discovery
func (m *LegacyArtifactManager) FindSBOMs(_ context.Context, subject name.Digest) ([]SBOMArtifact, error) {
	se, err := ociremote.SignedEntity(subject, m.opts...)
	if err != nil {
		// If entity not found, return empty slice (no SBOMs exist)
		return []SBOMArtifact{}, nil
	}

	// Use existing SBOM attachment mechanism
	file, err := se.Attachment("sbom")
	if err != nil {
		// If no SBOM attachment found, return empty slice
		return []SBOMArtifact{}, nil
	}

	mt, err := file.FileMediaType()
	if err != nil {
		return []SBOMArtifact{}, nil
	}

	payload, err := file.Payload()
	if err != nil {
		return []SBOMArtifact{}, nil
	}

	return []SBOMArtifact{{
		MediaType: string(mt),
		Content:   payload,
		Digest:    subject, // The attachment is linked to this subject
	}}, nil
}

// AttachSignature implements legacy signature attachment
func (m *LegacyArtifactManager) AttachSignature(_ context.Context, subject name.Digest, signature oci.Signature, _ AttachOptions) error {
	se, err := ociremote.SignedEntity(subject, m.opts...)
	if err != nil {
		return err
	}

	newSE, err := mutate.AttachSignatureToEntity(se, signature)
	if err != nil {
		return err
	}

	return ociremote.WriteSignatures(subject.Repository, newSE, m.opts...)
}

// AttachAttestation implements legacy attestation attachment
func (m *LegacyArtifactManager) AttachAttestation(_ context.Context, subject name.Digest, attestation oci.Signature, _ AttachOptions) error {
	se, err := ociremote.SignedEntity(subject, m.opts...)
	if err != nil {
		return err
	}

	newSE, err := mutate.AttachAttestationToEntity(se, attestation)
	if err != nil {
		return err
	}

	return ociremote.WriteAttestations(subject.Repository, newSE, m.opts...)
}

// AttachSBOM implements legacy SBOM attachment
func (m *LegacyArtifactManager) AttachSBOM(_ context.Context, subject name.Digest, sbom []byte, mediaType types.MediaType, _ AttachOptions) error {
	se, err := ociremote.SignedEntity(subject, m.opts...)
	if err != nil {
		return err
	}

	file, err := static.NewFile(sbom, static.WithLayerMediaType(mediaType))
	if err != nil {
		return err
	}
	newSE, err := mutate.AttachFileToEntity(se, "sbom", file)
	if err != nil {
		return err
	}

	return ociremote.WriteAttestations(subject.Repository, newSE, m.opts...)
}

// CreateAttestation implements legacy attestation creation and attachment
func (m *LegacyArtifactManager) CreateAttestation(_ context.Context, _ name.Digest, _ []byte, _ string, _ SigningOptions, _ AttachOptions) error {
	// Creating attestations requires complex signing logic that belongs in the CLI layer
	// This method should not be used - use AttachAttestation with a pre-created attestation instead
	return fmt.Errorf("CreateAttestation not implemented - use AttachAttestation instead")
}

// CreateSignature implements legacy signature creation and attachment
func (m *LegacyArtifactManager) CreateSignature(_ context.Context, _ name.Digest, _ []byte, _ SigningOptions, _ AttachOptions) error {
	// Creating signatures requires complex signing logic that belongs in the CLI layer
	// This method should not be used - use AttachSignature with a pre-created signature instead
	return fmt.Errorf("CreateSignature not implemented - use AttachSignature instead")
}

// FindBundles implements bundle discovery for legacy mode (not supported)
func (m *LegacyArtifactManager) FindBundles(_ context.Context, _ name.Digest) ([]BundleArtifact, error) {
	// Legacy storage mode does not support bundle format
	// Future: could potentially parse existing artifacts into bundle format for compatibility
	return []BundleArtifact{}, nil
}

// AttachBundle implements bundle attachment for legacy mode (not supported)
func (m *LegacyArtifactManager) AttachBundle(_ context.Context, _ name.Digest, _ BundleArtifact, _ AttachOptions) error {
	// Legacy storage mode does not support bundle format
	return fmt.Errorf("bundle format not supported in legacy storage mode")
}

// CreateBundle implements bundle creation for legacy mode (not supported)
func (m *LegacyArtifactManager) CreateBundle(_ context.Context, _ name.Digest, _ []byte, _ SigningOptions, _ AttachOptions) error {
	// Legacy storage mode does not support bundle format
	return fmt.Errorf("bundle format not supported in legacy storage mode")
}
