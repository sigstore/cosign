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

func TestFlagPrecedence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		registryMode      options.RegistryReferrersMode
		experimentalOCI11 bool
		expected          StorageMode
		description       string
	}{
		{
			name:              "Default to legacy",
			registryMode:      options.RegistryReferrersModeLegacy,
			experimentalOCI11: false,
			expected:          StorageModeLegacy,
			description:       "Both flags off should use legacy",
		},
		{
			name:              "Registry mode takes precedence",
			registryMode:      options.RegistryReferrersModeOCI11,
			experimentalOCI11: false,
			expected:          StorageModeOCI11,
			description:       "Registry mode should work even without experimental flag",
		},
		{
			name:              "Experimental flag alone works",
			registryMode:      options.RegistryReferrersModeLegacy,
			experimentalOCI11: true,
			expected:          StorageModeOCI11,
			description:       "Experimental flag should enable OCI 1.1",
		},
		{
			name:              "Both flags together work",
			registryMode:      options.RegistryReferrersModeOCI11,
			experimentalOCI11: true,
			expected:          StorageModeOCI11,
			description:       "Both flags together should enable OCI 1.1",
		},
		{
			name:              "Experimental flag overrides default registry mode",
			registryMode:      "", // Default empty value
			experimentalOCI11: true,
			expected:          StorageModeOCI11,
			description:       "Experimental flag should work with default registry mode",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			regExpOpts := options.RegistryExperimentalOptions{
				RegistryReferrersMode: tt.registryMode,
			}

			result := DetermineStorageMode(regExpOpts, tt.experimentalOCI11)
			if result != tt.expected {
				t.Errorf("DetermineStorageMode() = %v, want %v. %s", result, tt.expected, tt.description)
			}
		})
	}
}

func TestExperimentalFlagIsConvenience(t *testing.T) {
	t.Parallel()

	// Test that --experimental-oci11 is equivalent to --registry-referrers-mode=oci-1-1

	regExpOptsWithFlag := options.RegistryExperimentalOptions{
		RegistryReferrersMode: options.RegistryReferrersModeOCI11,
	}
	resultWithFlag := DetermineStorageMode(regExpOptsWithFlag, false)

	regExpOptsWithExperimental := options.RegistryExperimentalOptions{}
	resultWithExperimental := DetermineStorageMode(regExpOptsWithExperimental, true)

	if resultWithFlag != resultWithExperimental {
		t.Errorf("--experimental-oci11 should be equivalent to --registry-referrers-mode=oci-1-1. Got %v vs %v", resultWithExperimental, resultWithFlag)
	}

	if resultWithFlag != StorageModeOCI11 {
		t.Errorf("Both methods should result in OCI 1.1 mode, got %v", resultWithFlag)
	}
}

func TestBackwardCompatibility(t *testing.T) {
	t.Parallel()

	// Test that existing behavior is preserved when no new flags are used
	regExpOpts := options.RegistryExperimentalOptions{}

	result := DetermineStorageMode(regExpOpts, false)
	if result != StorageModeLegacy {
		t.Errorf("Default behavior should be legacy mode, got %v", result)
	}
}
