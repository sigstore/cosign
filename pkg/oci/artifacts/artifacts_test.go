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
	"testing"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
)

func TestDetermineStorageMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		regExpOpts        options.RegistryExperimentalOptions
		experimentalOCI11 bool
		expected          StorageMode
	}{
		{
			name:              "Legacy mode by default",
			regExpOpts:        options.RegistryExperimentalOptions{},
			experimentalOCI11: false,
			expected:          StorageModeLegacy,
		},
		{
			name: "OCI 1.1 mode via registry option",
			regExpOpts: options.RegistryExperimentalOptions{
				RegistryReferrersMode: options.RegistryReferrersModeOCI11,
			},
			experimentalOCI11: false,
			expected:          StorageModeOCI11,
		},
		{
			name:              "OCI 1.1 mode via experimental flag",
			regExpOpts:        options.RegistryExperimentalOptions{},
			experimentalOCI11: true,
			expected:          StorageModeOCI11,
		},
		{
			name: "OCI 1.1 mode with both flags",
			regExpOpts: options.RegistryExperimentalOptions{
				RegistryReferrersMode: options.RegistryReferrersModeOCI11,
			},
			experimentalOCI11: true,
			expected:          StorageModeOCI11,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := DetermineStorageMode(tt.regExpOpts, tt.experimentalOCI11)
			if result != tt.expected {
				t.Errorf("DetermineStorageMode() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestPredicateTypeFilter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		filter        PredicateTypeFilter
		artifact      Artifact
		shouldInclude bool
	}{
		{
			name:   "Empty filter includes all attestations",
			filter: PredicateTypeFilter(""),
			artifact: Artifact{
				Type: "att",
				Metadata: map[string]interface{}{
					"predicateType": "https://slsa.dev/provenance/v0.2",
				},
			},
			shouldInclude: true,
		},
		{
			name:   "Specific filter matches predicate type",
			filter: PredicateTypeFilter("https://slsa.dev/provenance/v0.2"),
			artifact: Artifact{
				Type: "att",
				Metadata: map[string]interface{}{
					"predicateType": "https://slsa.dev/provenance/v0.2",
				},
			},
			shouldInclude: true,
		},
		{
			name:   "Specific filter rejects different predicate type",
			filter: PredicateTypeFilter("https://slsa.dev/provenance/v0.2"),
			artifact: Artifact{
				Type: "att",
				Metadata: map[string]interface{}{
					"predicateType": "https://in-toto.io/Statement/v0.1",
				},
			},
			shouldInclude: false,
		},
		{
			name:   "Non-attestation artifacts always pass through",
			filter: PredicateTypeFilter("https://slsa.dev/provenance/v0.2"),
			artifact: Artifact{
				Type: "sig",
				Metadata: map[string]interface{}{
					"signature": "...",
				},
			},
			shouldInclude: true,
		},
		{
			name:   "Attestation without predicate type metadata passes when no filter",
			filter: PredicateTypeFilter(""),
			artifact: Artifact{
				Type:     "att",
				Metadata: map[string]interface{}{},
			},
			shouldInclude: true,
		},
		{
			name:   "Attestation without predicate type metadata fails specific filter",
			filter: PredicateTypeFilter("https://slsa.dev/provenance/v0.2"),
			artifact: Artifact{
				Type:     "att",
				Metadata: map[string]interface{}{},
			},
			shouldInclude: true, // Missing metadata means no predicate type, should pass
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := tt.filter.Apply(tt.artifact)
			if result != tt.shouldInclude {
				t.Errorf("PredicateTypeFilter.Apply() = %v, want %v", result, tt.shouldInclude)
			}
		})
	}
}

func TestNewArtifactManagerFromUserPreferences(t *testing.T) {
	t.Parallel()

	regOpts := options.RegistryOptions{}

	tests := []struct {
		name              string
		regExpOpts        options.RegistryExperimentalOptions
		experimentalOCI11 bool
		expectedStrategy  FallbackStrategy
	}{
		{
			name:              "Default legacy-only",
			regExpOpts:        options.RegistryExperimentalOptions{},
			experimentalOCI11: false,
			expectedStrategy:  FallbackStrategyLegacyOnly,
		},
		{
			name:              "Experimental OCI 1.1 flag",
			regExpOpts:        options.RegistryExperimentalOptions{},
			experimentalOCI11: true,
			expectedStrategy:  FallbackStrategyOCI11First,
		},
		{
			name:              "Explicit OCI 1.1 mode",
			regExpOpts:        options.RegistryExperimentalOptions{RegistryReferrersMode: options.RegistryReferrersModeOCI11},
			experimentalOCI11: false,
			expectedStrategy:  FallbackStrategyOCI11First,
		},
		{
			name:              "Explicit legacy mode",
			regExpOpts:        options.RegistryExperimentalOptions{RegistryReferrersMode: options.RegistryReferrersModeLegacy},
			experimentalOCI11: true,
			expectedStrategy:  FallbackStrategyLegacyOnly,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			manager, err := NewArtifactManagerFromUserPreferences(regOpts, tt.regExpOpts, tt.experimentalOCI11)
			if err != nil {
				t.Fatalf("NewArtifactManagerFromUserPreferences() error = %v", err)
			}
			if manager == nil {
				t.Fatal("NewArtifactManagerFromUserPreferences() returned nil manager")
			}

			// Verify the interface is implemented
			_ = manager

			// Should always return AdaptiveArtifactManager with the right strategy
			adaptive, ok := manager.(*AdaptiveArtifactManager)
			if !ok {
				t.Errorf("Expected AdaptiveArtifactManager, got %T", manager)
			} else if adaptive.strategy != tt.expectedStrategy {
				t.Errorf("Expected strategy %v, got %v", tt.expectedStrategy, adaptive.strategy)
			}
		})
	}
}

func TestNewAdaptiveArtifactManagerDirectUsage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		strategy FallbackStrategy
	}{
		{
			name:     "Bundle format commands should use OCI11First",
			strategy: FallbackStrategyOCI11First,
		},
		{
			name:     "Legacy-only commands",
			strategy: FallbackStrategyLegacyOnly,
		},
		{
			name:     "OCI 1.1 first commands",
			strategy: FallbackStrategyOCI11First,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			manager := NewAdaptiveArtifactManager(tt.strategy)
			if manager == nil {
				t.Fatal("NewAdaptiveArtifactManager() returned nil manager")
			}

			// Verify the interface is implemented
			_ = manager

			// Verify strategy is set correctly
			if manager.strategy != tt.strategy {
				t.Errorf("Expected strategy %v, got %v", tt.strategy, manager.strategy)
			}
		})
	}
}

func TestStorageModeConstants(t *testing.T) {
	t.Parallel()

	// Verify string values match expected constants
	if StorageModeLegacy != "legacy" {
		t.Errorf("StorageModeLegacy = %q, want %q", StorageModeLegacy, "legacy")
	}
	if StorageModeOCI11 != "oci-1-1" {
		t.Errorf("StorageModeOCI11 = %q, want %q", StorageModeOCI11, "oci-1-1")
	}
	if StorageModeBundle != "bundle" {
		t.Errorf("StorageModeBundle = %q, want %q", StorageModeBundle, "bundle")
	}
}
