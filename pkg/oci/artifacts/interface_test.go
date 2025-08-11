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

func TestDetermineFallbackStrategy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		regExpOpts      options.RegistryExperimentalOptions
		experimentalOCI bool
		expected        FallbackStrategy
		description     string
	}{
		{
			name: "User explicitly wants OCI 1.1",
			regExpOpts: options.RegistryExperimentalOptions{
				RegistryReferrersMode: options.RegistryReferrersModeOCI11,
			},
			experimentalOCI: false,
			expected:        FallbackStrategyOCI11First,
			description:     "User prefers modern approach but wants reliability",
		},
		{
			name: "User explicitly wants legacy",
			regExpOpts: options.RegistryExperimentalOptions{
				RegistryReferrersMode: options.RegistryReferrersModeLegacy,
			},
			experimentalOCI: false,
			expected:        FallbackStrategyLegacyOnly,
			description:     "Respect user's explicit choice for legacy",
		},
		{
			name:       "Default with experimental flag",
			regExpOpts: options.RegistryExperimentalOptions{
				// Empty - default mode
			},
			experimentalOCI: true,
			expected:        FallbackStrategyOCI11First,
			description:     "Experimental flag indicates user wants to try new features",
		},
		{
			name:       "Default without experimental flag",
			regExpOpts: options.RegistryExperimentalOptions{
				// Empty - default mode
			},
			experimentalOCI: false,
			expected:        FallbackStrategyLegacyOnly,
			description:     "Conservative default - stick with what has always worked",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := DetermineFallbackStrategy(tt.regExpOpts, tt.experimentalOCI)
			if result != tt.expected {
				t.Errorf("DetermineFallbackStrategy() = %v, expected %v", result, tt.expected)
			}
			t.Logf("Strategy rationale: %s", tt.description)
		})
	}
}

func TestUserPreferenceMapping(t *testing.T) {
	t.Parallel()

	// Test that the mapping from user intent to strategy is logical
	tests := []struct {
		userIntent string
		setup      func() (options.RegistryExperimentalOptions, bool)
		expected   FallbackStrategy
	}{
		{
			userIntent: "I want to use the new OCI 1.1 referrers API",
			setup: func() (options.RegistryExperimentalOptions, bool) {
				return options.RegistryExperimentalOptions{
					RegistryReferrersMode: options.RegistryReferrersModeOCI11,
				}, false
			},
			expected: FallbackStrategyOCI11First,
		},
		{
			userIntent: "I want to stick with legacy tag-based storage",
			setup: func() (options.RegistryExperimentalOptions, bool) {
				return options.RegistryExperimentalOptions{
					RegistryReferrersMode: options.RegistryReferrersModeLegacy,
				}, false
			},
			expected: FallbackStrategyLegacyOnly,
		},
		{
			userIntent: "I want cosign to just work with any registry",
			setup: func() (options.RegistryExperimentalOptions, bool) {
				return options.RegistryExperimentalOptions{}, false
			},
			expected: FallbackStrategyLegacyOnly,
		},
		{
			userIntent: "I'm experimenting with new features",
			setup: func() (options.RegistryExperimentalOptions, bool) {
				return options.RegistryExperimentalOptions{}, true
			},
			expected: FallbackStrategyOCI11First,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.userIntent, func(t *testing.T) {
			t.Parallel()
			regExpOpts, experimentalOCI := tt.setup()
			result := DetermineFallbackStrategy(regExpOpts, experimentalOCI)
			if result != tt.expected {
				t.Errorf("For user intent '%s', got strategy %v, expected %v",
					tt.userIntent, result, tt.expected)
			}
		})
	}
}
