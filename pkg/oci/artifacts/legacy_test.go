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

func TestLegacyArtifactManager_Interface(_ *testing.T) {
	manager := &LegacyArtifactManager{
		opts: []ociremote.Option{},
	}

	// Verify it implements the interface
	var _ ArtifactManager = manager
}

func TestLegacyArtifactManager_FindArtifacts_UnsupportedType(t *testing.T) {
	manager := &LegacyArtifactManager{
		opts: []ociremote.Option{},
	}

	digest, err := name.NewDigest("gcr.io/test@sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234")
	if err != nil {
		t.Fatalf("Failed to create test digest: %v", err)
	}

	ctx := context.Background()
	_, err = manager.FindArtifacts(ctx, digest, "unknown", nil)

	if err == nil {
		t.Error("Expected error for unsupported artifact type, got nil")
	}

	expectedMsg := "unsupported artifact type: unknown"
	if err.Error() != expectedMsg {
		t.Errorf("Expected error message %q, got %q", expectedMsg, err.Error())
	}
}

func TestLegacyArtifactManager_CreateMethods_NotImplemented(t *testing.T) {
	manager := &LegacyArtifactManager{
		opts: []ociremote.Option{},
	}

	digest, err := name.NewDigest("gcr.io/test@sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234")
	if err != nil {
		t.Fatalf("Failed to create test digest: %v", err)
	}

	ctx := context.Background()

	tests := []struct {
		name     string
		testFunc func() error
		expected string
	}{
		{
			name: "CreateAttestation",
			testFunc: func() error {
				return manager.CreateAttestation(ctx, digest, []byte("test"), "test-type", SigningOptions{}, AttachOptions{})
			},
			expected: "not implemented", // Creation methods are not implemented
		},
		{
			name: "CreateSignature",
			testFunc: func() error {
				return manager.CreateSignature(ctx, digest, []byte("test"), SigningOptions{}, AttachOptions{})
			},
			expected: "not implemented", // Creation methods are not implemented
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.testFunc()
			if err == nil {
				t.Error("Expected error for unimplemented method, got nil")
			}
			if !strings.Contains(err.Error(), tt.expected) {
				t.Errorf("Expected error message to contain %q, got %q", tt.expected, err.Error())
			}
		})
	}
}

func TestLegacyArtifactManager_CreateArtifact_AttestationWithoutOptions(t *testing.T) {
	manager := &LegacyArtifactManager{
		opts: []ociremote.Option{},
	}

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

func TestLegacyArtifactManager_AttachArtifact_UnsupportedType(t *testing.T) {
	manager := &LegacyArtifactManager{
		opts: []ociremote.Option{},
	}

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

func TestLegacyArtifactManager_AttachArtifact_InvalidSignature(t *testing.T) {
	manager := &LegacyArtifactManager{
		opts: []ociremote.Option{},
	}

	digest, err := name.NewDigest("gcr.io/test@sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234")
	if err != nil {
		t.Fatalf("Failed to create test digest: %v", err)
	}

	ctx := context.Background()
	artifact := Artifact{
		Type:    "sig",
		Content: []byte("invalid json"),
	}

	err = manager.AttachArtifact(ctx, digest, artifact, AttachOptions{})

	if err == nil {
		t.Error("Expected error for invalid signature artifact, got nil")
	}

	if err.Error() != "invalid signature artifact: invalid character 'i' looking for beginning of value" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestLegacyArtifactManager_AttachArtifact_InvalidAttestation(t *testing.T) {
	manager := &LegacyArtifactManager{
		opts: []ociremote.Option{},
	}

	digest, err := name.NewDigest("gcr.io/test@sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234")
	if err != nil {
		t.Fatalf("Failed to create test digest: %v", err)
	}

	ctx := context.Background()
	artifact := Artifact{
		Type:    "att",
		Content: []byte("invalid json"),
	}

	err = manager.AttachArtifact(ctx, digest, artifact, AttachOptions{})

	if err == nil {
		t.Error("Expected error for invalid attestation artifact, got nil")
	}

	if err.Error() != "invalid attestation artifact: invalid character 'i' looking for beginning of value" {
		t.Errorf("Unexpected error message: %v", err)
	}
}
