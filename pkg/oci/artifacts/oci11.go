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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/sigstore/cosign/v2/internal/pkg/oci/remote"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/oci"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
)

// OCI11ArtifactManager implements the ArtifactManager interface using OCI 1.1 referrers API
type OCI11ArtifactManager struct {
	opts []ociremote.Option
}

// FindArtifacts implements unified artifact discovery for OCI 1.1 mode
func (m *OCI11ArtifactManager) FindArtifacts(ctx context.Context, subject name.Digest, artifactType string, filters ...Filter) ([]Artifact, error) {
	switch artifactType {
	case "": // Find all referrer artifacts
		return m.findAllReferrerArtifacts(ctx, subject, filters...)
	case "sig":
		signatures, err := m.FindSignatures(ctx, subject)
		if err != nil {
			return nil, err
		}
		artifacts := make([]Artifact, 0)
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
		artifacts := make([]Artifact, 0)
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
		artifacts := make([]Artifact, 0)
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

// AttachArtifact implements unified artifact attachment for OCI 1.1 mode
func (m *OCI11ArtifactManager) AttachArtifact(ctx context.Context, subject name.Digest, artifact Artifact, opts AttachOptions) error {
	switch artifact.Type {
	case "sig":
		var sig cosign.SignedPayload
		if err := json.Unmarshal(artifact.Content, &sig); err != nil {
			return fmt.Errorf("invalid signature artifact: %w", err)
		}
		// Convert to oci.Signature for attachment
		return fmt.Errorf("OCI 1.1 signature attachment not yet implemented")
	case "att":
		var att cosign.AttestationPayload
		if err := json.Unmarshal(artifact.Content, &att); err != nil {
			return fmt.Errorf("invalid attestation artifact: %w", err)
		}
		// Convert to oci.Signature for attachment
		return fmt.Errorf("OCI 1.1 attestation attachment not yet implemented")
	case "sbom":
		mediaType := types.MediaType(artifact.MediaType)
		return m.AttachSBOM(ctx, subject, artifact.Content, mediaType, opts)
	default:
		return fmt.Errorf("unsupported artifact type for attachment: %s", artifact.Type)
	}
}

// CreateArtifact implements unified artifact creation for OCI 1.1 mode
func (m *OCI11ArtifactManager) CreateArtifact(ctx context.Context, subject name.Digest, content []byte, artifactType string, signingOpts SigningOptions, attachOpts AttachOptions) error {
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

// FindSignatures implements OCI 1.1 signature discovery
func (m *OCI11ArtifactManager) FindSignatures(_ context.Context, subject name.Digest) ([]cosign.SignedPayload, error) {
	artifactType := remote.ArtifactType("sig")
	indexManifest, err := ociremote.Referrers(subject, artifactType, m.opts...)
	if err != nil {
		// If referrers API fails or no referrers found, return empty slice
		return []cosign.SignedPayload{}, nil
	}

	signatures := make([]cosign.SignedPayload, 0)
	for _, manifest := range indexManifest.Manifests {
		if manifest.ArtifactType != artifactType {
			continue
		}

		// Fetch and process artifact
		artifactRef := subject.Context().Digest(manifest.Digest.String())
		artifact, err := ociremote.SignedImage(artifactRef, m.opts...)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error fetching artifact %s: %v\n", artifactRef, err)
			continue
		}

		layers, err := artifact.Layers()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error fetching layers for artifact %s: %v\n", artifactRef, err)
			continue
		}

		for _, layer := range layers {
			reader, err := layer.Compressed()
			if err != nil {
				continue
			}
			defer reader.Close()

			content, err := io.ReadAll(reader)
			if err != nil {
				continue
			}

			var signedPayload cosign.SignedPayload
			if err := json.Unmarshal(content, &signedPayload); err != nil {
				continue // Skip invalid artifacts
			}
			signatures = append(signatures, signedPayload)
		}
	}

	return signatures, nil
}

// FindAttestations implements OCI 1.1 attestation discovery
func (m *OCI11ArtifactManager) FindAttestations(_ context.Context, subject name.Digest, predicateType string) ([]cosign.AttestationPayload, error) {
	artifactType := remote.ArtifactType("att")
	indexManifest, err := ociremote.Referrers(subject, artifactType, m.opts...)
	if err != nil {
		// If referrers API fails or no referrers found, return empty slice
		return []cosign.AttestationPayload{}, nil
	}

	attestations := make([]cosign.AttestationPayload, 0)
	for _, manifest := range indexManifest.Manifests {
		if manifest.ArtifactType != artifactType {
			continue
		}

		// Fetch and process artifact
		artifactRef := subject.Context().Digest(manifest.Digest.String())
		artifact, err := ociremote.SignedImage(artifactRef, m.opts...)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error fetching artifact %s: %v\n", artifactRef, err)
			continue
		}

		layers, err := artifact.Layers()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error fetching layers for artifact %s: %v\n", artifactRef, err)
			continue
		}

		for _, layer := range layers {
			reader, err := layer.Compressed()
			if err != nil {
				continue
			}
			defer reader.Close()

			content, err := io.ReadAll(reader)
			if err != nil {
				continue
			}

			var attestationPayload cosign.AttestationPayload
			if err := json.Unmarshal(content, &attestationPayload); err != nil {
				continue // Skip invalid artifacts
			}

			// Filter by predicate type if specified
			if predicateType != "" {
				decodedPayload, err := base64.StdEncoding.DecodeString(attestationPayload.PayLoad)
				if err != nil {
					continue
				}
				var statement in_toto.Statement
				if err := json.Unmarshal(decodedPayload, &statement); err != nil {
					continue
				}
				if statement.PredicateType != predicateType {
					continue // Skip this attestation
				}
			}

			attestations = append(attestations, attestationPayload)
		}
	}

	return attestations, nil
}

// FindSBOMs implements OCI 1.1 SBOM discovery
func (m *OCI11ArtifactManager) FindSBOMs(_ context.Context, subject name.Digest) ([]SBOMArtifact, error) {
	artifactType := remote.ArtifactType("sbom")
	indexManifest, err := ociremote.Referrers(subject, artifactType, m.opts...)
	if err != nil {
		// If referrers API fails or no referrers found, return empty slice
		return []SBOMArtifact{}, nil
	}

	sboms := make([]SBOMArtifact, 0)
	for _, manifest := range indexManifest.Manifests {
		if manifest.ArtifactType != artifactType {
			continue
		}

		// Fetch SBOM artifact
		artifactRef := subject.Context().Digest(manifest.Digest.String())
		artifact, err := ociremote.SignedImage(artifactRef, m.opts...)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error fetching SBOM artifact %s: %v\n", artifactRef, err)
			continue
		}

		layers, err := artifact.Layers()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error fetching layers for SBOM artifact %s: %v\n", artifactRef, err)
			continue
		}

		for _, layer := range layers {
			mt, err := layer.MediaType()
			if err != nil {
				continue
			}

			reader, err := layer.Compressed()
			if err != nil {
				continue
			}
			defer reader.Close()

			content, err := io.ReadAll(reader)
			if err != nil {
				continue
			}

			sboms = append(sboms, SBOMArtifact{
				MediaType: string(mt),
				Content:   content,
				Digest:    artifactRef,
			})
		}
	}

	return sboms, nil
}

// AttachSignature implements OCI 1.1 signature attachment
func (m *OCI11ArtifactManager) AttachSignature(_ context.Context, _ name.Digest, _ oci.Signature, _ AttachOptions) error {
	// Implement OCI 1.1 referrers-based signature attachment
	return fmt.Errorf("OCI 1.1 signature attachment not yet implemented")
}

// AttachAttestation implements OCI 1.1 attestation attachment
func (m *OCI11ArtifactManager) AttachAttestation(_ context.Context, _ name.Digest, _ oci.Signature, _ AttachOptions) error {
	// Implement OCI 1.1 referrers-based attestation attachment
	return fmt.Errorf("OCI 1.1 attestation attachment not yet implemented")
}

// AttachSBOM implements OCI 1.1 SBOM attachment
func (m *OCI11ArtifactManager) AttachSBOM(_ context.Context, _ name.Digest, _ []byte, _ types.MediaType, _ AttachOptions) error {
	// Implement OCI 1.1 referrers-based SBOM attachment
	return fmt.Errorf("OCI 1.1 SBOM attachment not yet implemented")
}

// CreateAttestation implements OCI 1.1 attestation creation and attachment
func (m *OCI11ArtifactManager) CreateAttestation(_ context.Context, _ name.Digest, _ []byte, _ string, _ SigningOptions, _ AttachOptions) error {
	// Creating attestations requires complex signing logic that belongs in the CLI layer
	// This method should not be used - use AttachAttestation with a pre-created attestation instead
	return fmt.Errorf("CreateAttestation not implemented - use AttachAttestation instead")
}

// CreateSignature implements OCI 1.1 signature creation and attachment
func (m *OCI11ArtifactManager) CreateSignature(_ context.Context, _ name.Digest, _ []byte, _ SigningOptions, _ AttachOptions) error {
	// Creating signatures requires complex signing logic that belongs in the CLI layer
	// This method should not be used - use AttachSignature with a pre-created signature instead
	return fmt.Errorf("CreateSignature not implemented - use AttachSignature instead")
}

// findAllReferrerArtifacts finds all referrer artifacts for the subject, regardless of type
// This is useful for discovery operations like the tree command that want to show everything
func (m *OCI11ArtifactManager) findAllReferrerArtifacts(_ context.Context, subject name.Digest, filters ...Filter) ([]Artifact, error) {
	// Get all referrers without filtering by artifact type
	indexManifest, err := ociremote.Referrers(subject, "", m.opts...)
	if err != nil {
		// If referrers API fails or no referrers found, return empty slice
		return []Artifact{}, nil
	}

	artifacts := make([]Artifact, 0)
	for _, manifest := range indexManifest.Manifests {
		if manifest.ArtifactType == "" {
			continue // Skip manifests without artifact type
		}

		// Create a generic artifact for each referrer
		artifact := Artifact{
			Type:      "referrer", // Generic type for all referrers
			Content:   nil,        // Content not needed for tree display
			MediaType: manifest.ArtifactType,
			Digest:    subject.Context().Digest(manifest.Digest.String()),
			Metadata: map[string]interface{}{
				"manifestDigest": manifest.Digest.String(),
				"artifactType":   manifest.ArtifactType,
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
}

// FindBundles implements bundle discovery for OCI 1.1 mode (future)
func (m *OCI11ArtifactManager) FindBundles(_ context.Context, subject name.Digest) ([]BundleArtifact, error) {
	// Future: implement bundle discovery using OCI 1.1 referrers API
	// Will query for artifacts with bundle media type and parse protobuf content
	_ = subject // Avoid unused parameter warning
	return []BundleArtifact{}, nil
}

// AttachBundle implements bundle attachment for OCI 1.1 mode (future)
func (m *OCI11ArtifactManager) AttachBundle(_ context.Context, _ name.Digest, _ BundleArtifact, _ AttachOptions) error {
	// Future: implement bundle attachment using OCI 1.1 referrers
	return fmt.Errorf("OCI 1.1 bundle attachment not yet implemented")
}

// CreateBundle implements bundle creation for OCI 1.1 mode (future)
func (m *OCI11ArtifactManager) CreateBundle(_ context.Context, _ name.Digest, _ []byte, _ SigningOptions, _ AttachOptions) error {
	// Future: implement bundle creation and attachment
	return fmt.Errorf("OCI 1.1 bundle creation not yet implemented")
}
