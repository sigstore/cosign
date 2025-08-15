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
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/oci"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
)

// StorageMode represents how artifacts are stored and discovered in registries
type StorageMode string

const (
	StorageModeLegacy StorageMode = "legacy"  // Tag-based storage (.sig, .att, .sbom suffixes)
	StorageModeOCI11  StorageMode = "oci-1-1" // OCI 1.1 referrers API with adaptive fallback
	StorageModeBundle StorageMode = "bundle"  // Sigstore bundle format
)

// FallbackStrategy determines how the AdaptiveArtifactManager handles operations
type FallbackStrategy string

const (
	// FallbackStrategyOCI11First tries OCI 1.1 referrers API first, falls back to legacy tag-based storage.
	// Used when user prefers modern OCI 1.1 approach but wants compatibility with older registries.
	FallbackStrategyOCI11First FallbackStrategy = "oci11-first"

	// FallbackStrategyLegacyOnly uses only legacy tag-based storage (.sig, .att, .sbom suffixes).
	// Used when user explicitly wants legacy mode or for maximum backward compatibility.
	FallbackStrategyLegacyOnly FallbackStrategy = "legacy-only"
)

// ArtifactManager provides unified operations across storage modes and formats
// using a simplified three-interface design: Find + Attach + Create
type ArtifactManager interface {
	// Discovery operations - unified interface for all artifact types
	FindArtifacts(ctx context.Context, subject name.Digest, artifactType string, filters ...Filter) ([]Artifact, error)

	// Attach operations - unified interface for pre-existing artifacts
	AttachArtifact(ctx context.Context, subject name.Digest, artifact Artifact, opts AttachOptions) error

	// Create operations - unified interface for creating and attaching new artifacts
	CreateArtifact(ctx context.Context, subject name.Digest, content []byte, artifactType string, signingOpts SigningOptions, attachOpts AttachOptions) error

	// Legacy compatibility methods (thin wrappers around unified interface)
	FindSignatures(ctx context.Context, subject name.Digest) ([]cosign.SignedPayload, error)
	FindAttestations(ctx context.Context, subject name.Digest, predicateType string) ([]cosign.AttestationPayload, error)
	FindSBOMs(ctx context.Context, subject name.Digest) ([]SBOMArtifact, error)
	AttachSignature(ctx context.Context, subject name.Digest, signature oci.Signature, opts AttachOptions) error
	AttachAttestation(ctx context.Context, subject name.Digest, attestation oci.Signature, opts AttachOptions) error
	AttachSBOM(ctx context.Context, subject name.Digest, sbom []byte, mediaType types.MediaType, opts AttachOptions) error
	CreateAttestation(ctx context.Context, subject name.Digest, predicate []byte, predicateType string, signingOpts SigningOptions, attachOpts AttachOptions) error
	CreateSignature(ctx context.Context, subject name.Digest, payload []byte, signingOpts SigningOptions, attachOpts AttachOptions) error

	// Bundle format support (future-ready interfaces)
	FindBundles(ctx context.Context, subject name.Digest) ([]BundleArtifact, error)
	AttachBundle(ctx context.Context, subject name.Digest, bundle BundleArtifact, opts AttachOptions) error
	CreateBundle(ctx context.Context, subject name.Digest, bundleBytes []byte, signingOpts SigningOptions, attachOpts AttachOptions) error
}

// Artifact represents any artifact type with unified structure
type Artifact struct {
	Type      string                 // "sig", "att", "sbom", "bundle"
	Content   []byte                 // Raw content, JSON payload, or DSSE envelope
	MediaType string                 // OCI media type
	Digest    name.Digest            // Artifact digest
	Metadata  map[string]interface{} // Certificates, timestamps, predicate type, etc.
}

// BundleArtifact represents a Sigstore bundle format artifact
// Contains both the parsed content and the raw bundle for verification workflows
type BundleArtifact struct {
	Type        string                 // Always "bundle"
	Content     []byte                 // Parsed bundle content (signatures, attestations, etc.)
	MediaType   string                 // Bundle media type (e.g., "application/vnd.dev.sigstore.bundle.v0.3+json")
	Digest      name.Digest            // Bundle artifact digest
	Metadata    map[string]interface{} // Bundle metadata (version, verification material, etc.)
	BundleBytes []byte                 // Raw protobuf bundle bytes for verification
}

// Filter provides filtering capabilities for discovery
type Filter interface {
	Apply(artifact Artifact) bool
}

// PredicateTypeFilter filters attestations by predicate type
type PredicateTypeFilter string

func (f PredicateTypeFilter) Apply(artifact Artifact) bool {
	if artifact.Type != "att" {
		return true // Not an attestation, pass through
	}
	predicateType, ok := artifact.Metadata["predicateType"].(string)
	return !ok || predicateType == string(f) || string(f) == ""
}

// AttachOptions provides configuration for artifact attachment
type AttachOptions struct {
	RegistryOpts []ociremote.Option
	// Future: Bundle-specific options, encryption options, etc.
}

// SigningOptions provides unified configuration for artifact creation and signing
// Combines fields from both SignOptions and AttestOptions (95% overlap identified)
type SigningOptions struct {
	// Core signing fields (identical between signatures and attestations)
	KeyOpts         options.KeyOpts
	CertPath        string
	CertChainPath   string
	TSAServerURL    string
	RekorURL        string
	TlogUpload      bool
	Timeout         time.Duration
	NewBundleFormat bool

	// Type-specific fields (5% difference)
	SignSpecific   *SignSpecificOptions   // Upload, OutputSignature, etc.
	AttestSpecific *AttestSpecificOptions // Replace, RekorEntryType, etc.
	SBOMSpecific   *SBOMSpecificOptions   // Media type, format, etc.
}

// Type-specific options (thin wrappers for the 5% that differs)
type SignSpecificOptions struct {
	Upload                bool
	OutputSignature       string
	OutputPayload         string
	OutputCertificate     string
	PayloadPath           string
	Recursive             bool
	Attachment            string
	SignContainerIdentity string
	Annotations           map[string]interface{}
}

type AttestSpecificOptions struct {
	Replace        bool
	RekorEntryType string
	PredicateType  string
}

type SBOMSpecificOptions struct {
	MediaType types.MediaType
}

// Legacy compatibility types
type SBOMArtifact struct {
	MediaType string
	Content   []byte
	Digest    name.Digest
}

// NewAdaptiveArtifactManagerFromConfig creates an adaptive artifact manager that automatically
// determines the best strategy based on user preferences about referrers API usage.
// CLI commands should use this for standard signature/attestation operations.
//
// Note: Bundle format commands should use NewAdaptiveArtifactManager(FallbackStrategyOCI11First, opts...)
// directly instead of this function.
func NewAdaptiveArtifactManagerFromConfig(regOpts options.RegistryOptions, regExpOpts options.RegistryExperimentalOptions, experimentalOCI11 bool) (ArtifactManager, error) {
	ociOpts, err := regOpts.ClientOpts(context.Background())
	if err != nil {
		return nil, err
	}

	// Translate user preferences into optimal strategy
	strategy := DetermineFallbackStrategy(regExpOpts, experimentalOCI11)
	return NewAdaptiveArtifactManager(strategy, ociOpts...), nil
}

// NewArtifactManagerFromUserPreferences is the recommended factory function for standard CLI commands.
// It hides the strategy complexity and just asks: "what does the user want?"
//
// Note: Bundle format commands should use NewAdaptiveArtifactManager(FallbackStrategyOCI11First, opts...)
// directly instead of this function.
func NewArtifactManagerFromUserPreferences(regOpts options.RegistryOptions, regExpOpts options.RegistryExperimentalOptions, experimentalOCI11 bool) (ArtifactManager, error) {
	return NewAdaptiveArtifactManagerFromConfig(regOpts, regExpOpts, experimentalOCI11)
}

// Helper functions to determine mode and format from options
func DetermineStorageMode(regExpOpts options.RegistryExperimentalOptions, experimentalOCI11 bool) StorageMode {
	if regExpOpts.RegistryReferrersMode == options.RegistryReferrersModeOCI11 || experimentalOCI11 {
		return StorageModeOCI11
	}
	return StorageModeLegacy
}

// DetermineFallbackStrategy determines the appropriate fallback strategy based on user preferences
// for registry storage modes. This function handles OCI 1.1 vs legacy storage preferences.
//
// Note: Bundle format commands should directly use FallbackStrategyOCI11First instead of
// calling this function, since bundle format is an artifact format choice, not a storage mode choice.
// The CLI should not choose strategies directly - instead it expresses user intent and
// this function translates that into the optimal strategy.
func DetermineFallbackStrategy(regExpOpts options.RegistryExperimentalOptions, experimentalOCI11 bool) FallbackStrategy {
	switch regExpOpts.RegistryReferrersMode {
	case options.RegistryReferrersModeOCI11:
		// User explicitly wants OCI 1.1 referrers API
		// Strategy: Try OCI 1.1 first, but fall back to legacy for compatibility
		return FallbackStrategyOCI11First

	case options.RegistryReferrersModeLegacy:
		// User explicitly wants legacy tag-based storage
		// Strategy: Use only legacy mode (no fallback to OCI 1.1)
		return FallbackStrategyLegacyOnly

	default:
		// No explicit preference (most common case)
		// Strategy: Prefer legacy for backward compatibility
		if experimentalOCI11 {
			// Experimental flag set - user is trying new features
			// Try OCI 1.1 first but fall back to legacy for compatibility
			return FallbackStrategyOCI11First
		}
		// If nothing is configured, we default to legacy for backwards compatibility
		return FallbackStrategyLegacyOnly
	}
}
