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
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
)

func TestAdaptiveArtifactManager_Interface(_ *testing.T) {
	manager := NewAdaptiveArtifactManager(FallbackStrategyOCI11First)

	// Verify it implements the interface
	var _ ArtifactManager = manager
}

func TestNewAdaptiveArtifactManager(t *testing.T) {
	opts := []ociremote.Option{}
	manager := NewAdaptiveArtifactManager(FallbackStrategyOCI11First, opts...)

	if manager == nil {
		t.Fatal("NewAdaptiveArtifactManager() returned nil")
	}

	if manager.oci11 == nil {
		t.Error("oci11 manager is nil")
	}

	if manager.legacy == nil {
		t.Error("legacy manager is nil")
	}

	if manager.strategy != FallbackStrategyOCI11First {
		t.Errorf("Expected strategy %v, got %v", FallbackStrategyOCI11First, manager.strategy)
	}

	// Verify it implements the interface
	var _ ArtifactManager = manager
}

func TestAdaptiveArtifactManager_FallbackStrategies(t *testing.T) {
	tests := []struct {
		name     string
		strategy FallbackStrategy
	}{
		{"OCI11 First", FallbackStrategyOCI11First},
		{"Legacy Only", FallbackStrategyLegacyOnly},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := NewAdaptiveArtifactManager(tt.strategy)
			if manager.strategy != tt.strategy {
				t.Errorf("Expected strategy %v, got %v", tt.strategy, manager.strategy)
			}
		})
	}
}

func TestAdaptiveArtifactManager_CreateMethods_ErrorHandling(t *testing.T) {
	manager := NewAdaptiveArtifactManager(FallbackStrategyOCI11First)

	digest, err := name.NewDigest("gcr.io/test@sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234")
	if err != nil {
		t.Fatalf("Failed to create test digest: %v", err)
	}

	ctx := context.Background()

	tests := []struct {
		name     string
		testFunc func() error
	}{
		{
			name: "CreateAttestation",
			testFunc: func() error {
				return manager.CreateAttestation(ctx, digest, []byte("test"), "test-type", SigningOptions{}, AttachOptions{})
			},
		},
		{
			name: "CreateSignature",
			testFunc: func() error {
				return manager.CreateSignature(ctx, digest, []byte("test"), SigningOptions{}, AttachOptions{})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.testFunc()
			if err == nil {
				t.Error("Expected error for unimplemented method, got nil")
			}
			// Should contain "not implemented" since creation methods are not implemented
			if !strings.Contains(err.Error(), "not implemented") {
				t.Errorf("Expected error message to contain \"not implemented\", got %q", err.Error())
			}
		})
	}
}

func TestAdaptiveArtifactManager_CreateArtifact_AttestationWithoutOptions(t *testing.T) {
	manager := NewAdaptiveArtifactManager(FallbackStrategyOCI11First)

	digest, err := name.NewDigest("gcr.io/test@sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234")
	if err != nil {
		t.Fatalf("Failed to create test digest: %v", err)
	}

	ctx := context.Background()
	signingOpts := SigningOptions{
		AttestSpecific: nil, // Missing required options
	}

	err = manager.CreateArtifact(ctx, digest, []byte("test"), "att", signingOpts, AttachOptions{})

	if err == nil {
		t.Error("Expected error for missing AttestSpecific options, got nil")
	}

	expectedMsg := "attestation creation requires AttestSpecific options"
	if err.Error() != expectedMsg {
		t.Errorf("Expected error message %q, got %q", expectedMsg, err.Error())
	}
}

func TestAdaptiveArtifactManager_AttachArtifact_UnsupportedType(t *testing.T) {
	manager := NewAdaptiveArtifactManager(FallbackStrategyOCI11First)

	digest, err := name.NewDigest("gcr.io/test@sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234")
	if err != nil {
		t.Fatalf("Failed to create test digest: %v", err)
	}

	ctx := context.Background()
	artifact := Artifact{
		Type:    "unknown",
		Content: []byte("test"),
	}

	err = manager.AttachArtifact(ctx, digest, artifact, AttachOptions{})

	if err == nil {
		t.Error("Expected error for unsupported artifact type, got nil")
	}

	expectedMsg := "unsupported artifact type for attachment: unknown"
	if err.Error() != expectedMsg {
		t.Errorf("Expected error message %q, got %q", expectedMsg, err.Error())
	}
}
