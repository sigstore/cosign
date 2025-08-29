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

package remote

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/cosign/v2/pkg/oci/mutate"
	"github.com/sigstore/cosign/v2/pkg/oci/signed"
	cosignstatic "github.com/sigstore/cosign/v2/pkg/oci/static"
	ctypes "github.com/sigstore/cosign/v2/pkg/types"
)

func TestWriteSignatures(t *testing.T) {
	rw := remote.Write
	t.Cleanup(func() {
		remoteWrite = rw
	})
	i, err := random.Image(300 /* byteSize */, 7 /* layers */)
	if err != nil {
		t.Fatalf("random.Image() = %v", err)
	}
	si := signed.Image(i)

	want := 6 // Add 6 signatures
	for i := 0; i < want; i++ {
		sig, err := cosignstatic.NewSignature(nil, fmt.Sprintf("%d", i))
		if err != nil {
			t.Fatalf("static.NewSignature() = %v", err)
		}
		si, err = mutate.AttachSignatureToImage(si, sig)
		if err != nil {
			t.Fatalf("SignEntity() = %v", err)
		}
	}

	ref := name.MustParseReference("gcr.io/bistroless/static:nonroot")

	remoteWrite = func(_ name.Reference, img v1.Image, _ ...remote.Option) error {
		l, err := img.Layers()
		if err != nil {
			return err
		}

		if got := len(l); got != want {
			t.Errorf("got %d layers, wanted %d", got, want)
		}

		return nil
	}
	if err := WriteSignatures(ref.Context(), si); err != nil {
		t.Fatalf("WriteSignature() = %v", err)
	}
}

func TestWriteAttestations(t *testing.T) {
	rw := remote.Write
	t.Cleanup(func() {
		remoteWrite = rw
	})
	i, err := random.Image(300 /* byteSize */, 7 /* layers */)
	if err != nil {
		t.Fatalf("random.Image() = %v", err)
	}
	si := signed.Image(i)

	want := 6 // Add 6 attestations
	for i := 0; i < want; i++ {
		sig, err := cosignstatic.NewAttestation([]byte(fmt.Sprintf("%d", i)))
		if err != nil {
			t.Fatalf("static.NewSignature() = %v", err)
		}
		si, err = mutate.AttachAttestationToImage(si, sig)
		if err != nil {
			t.Fatalf("SignEntity() = %v", err)
		}
	}

	ref := name.MustParseReference("gcr.io/bistroless/static:nonroot")

	remoteWrite = func(_ name.Reference, img v1.Image, _ ...remote.Option) error {
		l, err := img.Layers()
		if err != nil {
			return err
		}

		if got := len(l); got != want {
			t.Errorf("got %d layers, wanted %d", got, want)
		}

		return nil
	}
	if err := WriteAttestations(ref.Context(), si); err != nil {
		t.Fatalf("WriteAttestations() = %v", err)
	}
}

func TestReferrerManifest(t *testing.T) {
	// Test referrerManifest.RawManifest()
	rm := referrerManifest{
		Manifest: v1.Manifest{
			SchemaVersion: 2,
			MediaType:     types.OCIManifestSchema1,
			Config: v1.Descriptor{
				MediaType: "application/vnd.oci.empty.v1+json",
				Digest:    v1.Hash{Algorithm: "sha256", Hex: "abc123"},
				Size:      100,
			},
			Layers: []v1.Descriptor{},
		},
		ArtifactType: "test.artifact.type",
	}

	manifestBytes, err := rm.RawManifest()
	if err != nil {
		t.Fatalf("RawManifest() = %v", err)
	}

	if len(manifestBytes) == 0 {
		t.Error("RawManifest returned empty bytes")
	}

	// Test referrerManifest.MediaType()
	mediaType, err := rm.MediaType()
	if err != nil {
		t.Fatalf("MediaType() = %v", err)
	}
	if mediaType != types.OCIManifestSchema1 {
		t.Errorf("MediaType() = %s, want %s", mediaType, types.OCIManifestSchema1)
	}

	// Test referrerManifest.targetRef()
	repo := name.MustParseReference("gcr.io/test/repo").Context()
	targetRef, err := rm.targetRef(repo)
	if err != nil {
		t.Fatalf("targetRef() = %v", err)
	}
	if targetRef == nil {
		t.Error("targetRef returned nil")
	}
}

func TestTaggableManifest(t *testing.T) {
	// Test taggableManifest.RawManifest()
	tm := taggableManifest{
		raw:       []byte(`{"test":"manifest"}`),
		mediaType: types.DockerManifestSchema2,
	}

	manifestBytes, err := tm.RawManifest()
	if err != nil {
		t.Fatalf("RawManifest() = %v", err)
	}
	if string(manifestBytes) != `{"test":"manifest"}` {
		t.Errorf("RawManifest() = %s, want %s", string(manifestBytes), `{"test":"manifest"}`)
	}

	// Test taggableManifest.MediaType()
	mediaType, err := tm.MediaType()
	if err != nil {
		t.Fatalf("MediaType() = %v", err)
	}
	if mediaType != types.DockerManifestSchema2 {
		t.Errorf("MediaType() = %s, want %s", mediaType, types.DockerManifestSchema2)
	}
}

func TestWriteAttestationNewBundleFormat(t *testing.T) {
	// Save original functions
	origHead := remoteHead
	origWriteLayer := remoteWriteLayer
	origPut := remotePut
	t.Cleanup(func() {
		remoteHead = origHead
		remoteWriteLayer = origWriteLayer
		remotePut = origPut
	})

	bundleBytes := []byte(`{"payload":"test","signatures":[]}`)
	predicateType := "https://test.predicate.type"
	digest := name.MustParseReference("gcr.io/test/image@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").(name.Digest)

	// Mock remoteHead to return a descriptor
	remoteHead = func(name.Reference, ...remote.Option) (*v1.Descriptor, error) {
		return &v1.Descriptor{
			MediaType: types.DockerManifestSchema2,
			Digest:    v1.Hash{Algorithm: "sha256", Hex: "abcdef1234567890"},
			Size:      100,
		}, nil
	}

	// Mock remoteWriteLayer to succeed
	remoteWriteLayer = func(name.Repository, v1.Layer, ...remote.Option) error {
		return nil
	}

	// Mock remotePut to capture the manifest
	var capturedManifest remote.Taggable
	remotePut = func(_ name.Reference, manifest remote.Taggable, _ ...remote.Option) error {
		capturedManifest = manifest
		return nil
	}

	err := WriteAttestationNewBundleFormat(digest, bundleBytes, predicateType)
	if err != nil {
		t.Fatalf("WriteAttestationNewBundleFormat() = %v", err)
	}

	// Verify that a manifest was uploaded
	if capturedManifest == nil {
		t.Error("Expected manifest to be uploaded, but none was captured")
	}

	// Verify it's a referrerManifest
	refManifest, ok := capturedManifest.(referrerManifest)
	if !ok {
		t.Errorf("Expected referrerManifest, got %T", capturedManifest)
		return
	}

	// Verify the artifact type contains bundle media type
	if refManifest.ArtifactType == "" {
		t.Error("Expected ArtifactType to be set")
	}

	// Verify annotations are set correctly
	if refManifest.Annotations["dev.sigstore.bundle.content"] != "dsse-envelope" {
		t.Errorf("Expected bundle.content annotation to be 'dsse-envelope', got %s", refManifest.Annotations["dev.sigstore.bundle.content"])
	}
	if refManifest.Annotations["dev.sigstore.bundle.predicateType"] != predicateType {
		t.Errorf("Expected predicateType annotation to be %s, got %s", predicateType, refManifest.Annotations["dev.sigstore.bundle.predicateType"])
	}
}

func TestWriteAttestationsReferrer(t *testing.T) {
	// Save original functions
	origHead := remoteHead
	origWriteLayer := remoteWriteLayer
	origPut := remotePut
	t.Cleanup(func() {
		remoteHead = origHead
		remoteWriteLayer = origWriteLayer
		remotePut = origPut
	})

	digest := name.MustParseReference("gcr.io/test/image@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").(name.Digest)

	// Create a test signed entity with attestations
	i, err := random.Image(300, 1)
	if err != nil {
		t.Fatalf("random.Image() = %v", err)
	}
	si := signed.Image(i)

	// Add an attestation
	att, err := cosignstatic.NewAttestation([]byte("test-attestation"))
	if err != nil {
		t.Fatalf("static.NewAttestation() = %v", err)
	}
	si, err = mutate.AttachAttestationToImage(si, att)
	if err != nil {
		t.Fatalf("AttachAttestationToImage() = %v", err)
	}

	// Mock remoteHead to return a descriptor
	remoteHead = func(name.Reference, ...remote.Option) (*v1.Descriptor, error) {
		return &v1.Descriptor{
			MediaType: types.DockerManifestSchema2,
			Digest:    v1.Hash{Algorithm: "sha256", Hex: "abcdef1234567890"},
			Size:      100,
		}, nil
	}

	// Mock remoteWriteLayer to succeed
	remoteWriteLayer = func(name.Repository, v1.Layer, ...remote.Option) error {
		return nil
	}

	// Mock remotePut to capture the manifest
	var capturedManifest remote.Taggable
	remotePut = func(_ name.Reference, manifest remote.Taggable, _ ...remote.Option) error {
		capturedManifest = manifest
		return nil
	}

	err = WriteAttestationsReferrer(digest, si)
	if err != nil {
		t.Fatalf("WriteAttestationsReferrer() = %v", err)
	}

	// Verify that a manifest was uploaded
	if capturedManifest == nil {
		t.Error("Expected manifest to be uploaded, but none was captured")
	}

	// Verify it's a referrerManifest
	refManifest, ok := capturedManifest.(referrerManifest)
	if !ok {
		t.Errorf("Expected referrerManifest, got %T", capturedManifest)
		return
	}

	// Verify the artifact type is set to in-toto payload type
	if refManifest.ArtifactType != ctypes.IntotoPayloadType {
		t.Errorf("Expected ArtifactType to be %s, got %s", ctypes.IntotoPayloadType, refManifest.ArtifactType)
	}

	// Verify annotations include created timestamp
	if _, exists := refManifest.Annotations["org.opencontainers.image.created"]; !exists {
		t.Error("Expected created annotation to be set")
	}

	// Verify we have at least one layer
	if len(refManifest.Layers) == 0 {
		t.Error("Expected at least one layer in manifest")
	}
}

func TestWriteReferrer(t *testing.T) {
	// Save original functions
	origHead := remoteHead
	origWriteLayer := remoteWriteLayer
	origPut := remotePut
	t.Cleanup(func() {
		remoteHead = origHead
		remoteWriteLayer = origWriteLayer
		remotePut = origPut
	})

	digest := name.MustParseReference("gcr.io/test/image@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").(name.Digest)

	// Create a test layer
	testLayer := static.NewLayer([]byte("test-data"), "application/octet-stream")
	layers := []v1.Layer{testLayer}
	annotations := map[string]string{
		"test.annotation": "test-value",
	}
	artifactType := "test.artifact.type"

	// Mock remoteHead to return a descriptor
	remoteHead = func(name.Reference, ...remote.Option) (*v1.Descriptor, error) {
		return &v1.Descriptor{
			MediaType: types.DockerManifestSchema2,
			Digest:    v1.Hash{Algorithm: "sha256", Hex: "abcdef1234567890"},
			Size:      100,
		}, nil
	}

	// Mock remoteWriteLayer to succeed
	remoteWriteLayer = func(name.Repository, v1.Layer, ...remote.Option) error {
		return nil
	}

	// Mock remotePut to capture the manifest
	var capturedManifest remote.Taggable
	remotePut = func(_ name.Reference, manifest remote.Taggable, _ ...remote.Option) error {
		capturedManifest = manifest
		return nil
	}

	err := WriteReferrer(digest, artifactType, layers, annotations)
	if err != nil {
		t.Fatalf("WriteReferrer() = %v", err)
	}

	// Verify that a manifest was uploaded
	if capturedManifest == nil {
		t.Error("Expected manifest to be uploaded, but none was captured")
	}

	// Verify it's a referrerManifest
	refManifest, ok := capturedManifest.(referrerManifest)
	if !ok {
		t.Errorf("Expected referrerManifest, got %T", capturedManifest)
		return
	}

	// Verify the artifact type is set correctly
	if refManifest.ArtifactType != artifactType {
		t.Errorf("Expected ArtifactType to be %s, got %s", artifactType, refManifest.ArtifactType)
	}

	// Verify annotations are passed through
	if refManifest.Annotations["test.annotation"] != "test-value" {
		t.Errorf("Expected annotation to be 'test-value', got %s", refManifest.Annotations["test.annotation"])
	}

	// Verify we have the expected number of layers
	if len(refManifest.Layers) != 1 {
		t.Errorf("Expected 1 layer, got %d", len(refManifest.Layers))
	}

	// Verify the subject is set
	if refManifest.Subject == nil {
		t.Error("Expected Subject to be set")
	}

	// Verify config descriptor
	if refManifest.Config.ArtifactType != artifactType {
		t.Errorf("Expected Config.ArtifactType to be %s, got %s", artifactType, refManifest.Config.ArtifactType)
	}
}

func TestWriteReferrerErrorHandling(t *testing.T) {
	// Save original functions
	origHead := remoteHead
	t.Cleanup(func() {
		remoteHead = origHead
	})

	digest := name.MustParseReference("gcr.io/test/image@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").(name.Digest)
	layers := []v1.Layer{}
	annotations := map[string]string{}

	// Mock remoteHead to return an error
	remoteHead = func(name.Reference, ...remote.Option) (*v1.Descriptor, error) {
		return nil, fmt.Errorf("remote head failed")
	}

	err := WriteReferrer(digest, "test.type", layers, annotations)
	if err == nil {
		t.Error("Expected error from WriteReferrer when remoteHead fails")
	}
	if !strings.Contains(err.Error(), "remote head failed") {
		t.Errorf("Expected error to contain 'remote head failed', got %v", err)
	}
}
