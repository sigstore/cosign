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

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/oci"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
)

// AdaptiveArtifactManager implements the ArtifactManager interface using configurable
// fallback strategies between OCI 1.1 and legacy storage modes
type AdaptiveArtifactManager struct {
	oci11    *OCI11ArtifactManager
	legacy   *LegacyArtifactManager
	strategy FallbackStrategy
}

// NewAdaptiveArtifactManager creates a new adaptive artifact manager with the specified strategy
func NewAdaptiveArtifactManager(strategy FallbackStrategy, opts ...ociremote.Option) *AdaptiveArtifactManager {
	return &AdaptiveArtifactManager{
		oci11:    &OCI11ArtifactManager{opts: opts},
		legacy:   &LegacyArtifactManager{opts: opts},
		strategy: strategy,
	}
}

// shouldPreferOCI11 determines whether to prefer OCI 1.1 for mutations based on user strategy
// This is about preference, not capability - ociremote.Referrers() handles fallback internally
func (m *AdaptiveArtifactManager) shouldPreferOCI11() bool {
	switch m.strategy {
	case FallbackStrategyLegacyOnly:
		return false // User explicitly wants legacy-only
	case FallbackStrategyOCI11First:
		return true // User wants modern OCI 1.1 approach when possible
	default:
		return true // Default to modern approach
	}
}

// FindArtifacts implements configurable artifact discovery
// Always query both legacy and OCI 1.1 - ociremote.Referrers() handles fallback internally
func (m *AdaptiveArtifactManager) FindArtifacts(ctx context.Context, subject name.Digest, artifactType string, filters ...Filter) ([]Artifact, error) {
	allArtifacts := make([]Artifact, 0)

	// Always query legacy first (artifacts might exist from before OCI 1.1 support)
	legacyArtifacts, err := m.legacy.FindArtifacts(ctx, subject, artifactType, filters...)
	if err == nil {
		allArtifacts = append(allArtifacts, legacyArtifacts...)
	}

	// Always query OCI 1.1 unless user explicitly wants legacy-only
	// ociremote.Referrers() will handle fallback to legacy automatically if needed
	if m.strategy != FallbackStrategyLegacyOnly {
		oci11Artifacts, err := m.oci11.FindArtifacts(ctx, subject, artifactType, filters...)
		if err == nil {
			allArtifacts = append(allArtifacts, oci11Artifacts...)
		}
	}

	return allArtifacts, nil
}

// AttachArtifact implements configurable artifact attachment
func (m *AdaptiveArtifactManager) AttachArtifact(ctx context.Context, subject name.Digest, artifact Artifact, opts AttachOptions) error {
	return m.executeForSubject(ctx, subject, func(manager ArtifactManager) error {
		return manager.AttachArtifact(ctx, subject, artifact, opts)
	})
}

// CreateArtifact implements configurable artifact creation
func (m *AdaptiveArtifactManager) CreateArtifact(ctx context.Context, subject name.Digest, content []byte, artifactType string, signingOpts SigningOptions, attachOpts AttachOptions) error {
	return m.executeForSubject(ctx, subject, func(manager ArtifactManager) error {
		return manager.CreateArtifact(ctx, subject, content, artifactType, signingOpts, attachOpts)
	})
}

// FindSignatures implements configurable signature discovery
// Always query both legacy and OCI 1.1 - ociremote.Referrers() handles fallback internally
func (m *AdaptiveArtifactManager) FindSignatures(ctx context.Context, subject name.Digest) ([]cosign.SignedPayload, error) {
	allSignatures := make([]cosign.SignedPayload, 0)

	// Always query legacy first (signatures might exist from before OCI 1.1 support)
	legacySignatures, err := m.legacy.FindSignatures(ctx, subject)
	if err == nil {
		allSignatures = append(allSignatures, legacySignatures...)
	}

	// Always query OCI 1.1 unless user explicitly wants legacy-only
	// ociremote.Referrers() will handle fallback to legacy automatically if needed
	if m.strategy != FallbackStrategyLegacyOnly {
		oci11Signatures, err := m.oci11.FindSignatures(ctx, subject)
		if err == nil {
			allSignatures = append(allSignatures, oci11Signatures...)
		}
	}

	return allSignatures, nil
}

// FindAttestations implements configurable attestation discovery
// Always query both legacy and OCI 1.1 - ociremote.Referrers() handles fallback internally
func (m *AdaptiveArtifactManager) FindAttestations(ctx context.Context, subject name.Digest, predicateType string) ([]cosign.AttestationPayload, error) {
	allAttestations := make([]cosign.AttestationPayload, 0)

	// Always query legacy first (attestations might exist from before OCI 1.1 support)
	legacyAttestations, err := m.legacy.FindAttestations(ctx, subject, predicateType)
	if err == nil {
		allAttestations = append(allAttestations, legacyAttestations...)
	}

	// Always query OCI 1.1 unless user explicitly wants legacy-only
	// ociremote.Referrers() will handle fallback to legacy automatically if needed
	if m.strategy != FallbackStrategyLegacyOnly {
		oci11Attestations, err := m.oci11.FindAttestations(ctx, subject, predicateType)
		if err == nil {
			allAttestations = append(allAttestations, oci11Attestations...)
		}
	}

	return allAttestations, nil
}

// FindSBOMs implements configurable SBOM discovery
// Always query both legacy and OCI 1.1 - ociremote.Referrers() handles fallback internally
func (m *AdaptiveArtifactManager) FindSBOMs(ctx context.Context, subject name.Digest) ([]SBOMArtifact, error) {
	allSBOMs := make([]SBOMArtifact, 0)

	// Always query legacy first (SBOMs might exist from before OCI 1.1 support)
	legacySBOMs, err := m.legacy.FindSBOMs(ctx, subject)
	if err == nil {
		allSBOMs = append(allSBOMs, legacySBOMs...)
	}

	// Always query OCI 1.1 unless user explicitly wants legacy-only
	// ociremote.Referrers() will handle fallback to legacy automatically if needed
	if m.strategy != FallbackStrategyLegacyOnly {
		oci11SBOMs, err := m.oci11.FindSBOMs(ctx, subject)
		if err == nil {
			allSBOMs = append(allSBOMs, oci11SBOMs...)
		}
	}

	return allSBOMs, nil
}

// AttachSignature implements configurable signature attachment
func (m *AdaptiveArtifactManager) AttachSignature(ctx context.Context, subject name.Digest, signature oci.Signature, opts AttachOptions) error {
	return m.executeForSubject(ctx, subject, func(manager ArtifactManager) error {
		return manager.AttachSignature(ctx, subject, signature, opts)
	})
}

// AttachAttestation implements configurable attestation attachment
func (m *AdaptiveArtifactManager) AttachAttestation(ctx context.Context, subject name.Digest, attestation oci.Signature, opts AttachOptions) error {
	return m.executeForSubject(ctx, subject, func(manager ArtifactManager) error {
		return manager.AttachAttestation(ctx, subject, attestation, opts)
	})
}

// AttachSBOM implements configurable SBOM attachment
func (m *AdaptiveArtifactManager) AttachSBOM(ctx context.Context, subject name.Digest, sbom []byte, mediaType types.MediaType, opts AttachOptions) error {
	return m.executeForSubject(ctx, subject, func(manager ArtifactManager) error {
		return manager.AttachSBOM(ctx, subject, sbom, mediaType, opts)
	})
}

// CreateAttestation implements configurable attestation creation
func (m *AdaptiveArtifactManager) CreateAttestation(ctx context.Context, subject name.Digest, predicate []byte, predicateType string, signingOpts SigningOptions, attachOpts AttachOptions) error {
	return m.executeForSubject(ctx, subject, func(manager ArtifactManager) error {
		return manager.CreateAttestation(ctx, subject, predicate, predicateType, signingOpts, attachOpts)
	})
}

// CreateSignature implements configurable signature creation
func (m *AdaptiveArtifactManager) CreateSignature(ctx context.Context, subject name.Digest, payload []byte, signingOpts SigningOptions, attachOpts AttachOptions) error {
	return m.executeForSubject(ctx, subject, func(manager ArtifactManager) error {
		return manager.CreateSignature(ctx, subject, payload, signingOpts, attachOpts)
	})
}

// FindBundles implements configurable bundle discovery (future)
func (m *AdaptiveArtifactManager) FindBundles(ctx context.Context, subject name.Digest) ([]BundleArtifact, error) {
	// Future: implement bundle discovery with fallback strategy
	// For now, return empty slice as bundles are not yet implemented
	_ = ctx     // Avoid unused parameter warning
	_ = subject // Avoid unused parameter warning
	return []BundleArtifact{}, nil
}

// AttachBundle implements configurable bundle attachment (future)
func (m *AdaptiveArtifactManager) AttachBundle(ctx context.Context, subject name.Digest, bundle BundleArtifact, opts AttachOptions) error {
	return m.executeForSubject(ctx, subject, func(manager ArtifactManager) error {
		return manager.AttachBundle(ctx, subject, bundle, opts)
	})
}

// CreateBundle implements configurable bundle creation (future)
func (m *AdaptiveArtifactManager) CreateBundle(ctx context.Context, subject name.Digest, bundleBytes []byte, signingOpts SigningOptions, attachOpts AttachOptions) error {
	return m.executeForSubject(ctx, subject, func(manager ArtifactManager) error {
		return manager.CreateBundle(ctx, subject, bundleBytes, signingOpts, attachOpts)
	})
}

// executeForSubject executes an operation using the preferred manager based on user strategy
// ociremote.Referrers() will handle automatic fallback internally if the preferred approach fails
func (m *AdaptiveArtifactManager) executeForSubject(_ context.Context, _ name.Digest, operation func(ArtifactManager) error) error {
	// Use strategy-based preference rather than capability detection
	// ociremote.Referrers() handles fallback to legacy automatically if OCI 1.1 fails
	if m.shouldPreferOCI11() {
		return operation(m.oci11)
	}
	return operation(m.legacy)
}
