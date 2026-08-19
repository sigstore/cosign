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
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/sigstore/cosign/v3/pkg/oci/mutate"
	"github.com/sigstore/cosign/v3/pkg/oci/signed"
	cosignstatic "github.com/sigstore/cosign/v3/pkg/oci/static"
	ctypes "github.com/sigstore/cosign/v3/pkg/types"
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

func TestWriteAttestationsReferrerPreservesAnnotations(t *testing.T) {
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

	// Create a test signed entity with attestations that have annotations
	i, err := random.Image(300, 1)
	if err != nil {
		t.Fatalf("random.Image() = %v", err)
	}
	si := signed.Image(i)

	// Create attestation with certificate chain and custom annotations
	certPEM := []byte("-----BEGIN CERTIFICATE-----\ntest-cert\n-----END CERTIFICATE-----\n")
	chainPEM := []byte("-----BEGIN CERTIFICATE-----\ntest-chain\n-----END CERTIFICATE-----\n")
	att, err := cosignstatic.NewAttestation([]byte("test-attestation"),
		cosignstatic.WithCertChain(certPEM, chainPEM),
		cosignstatic.WithAnnotations(map[string]string{
			"predicateType": "https://cosign.sigstore.dev/attestation/v1",
		}),
	)
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
		t.Fatal("Expected manifest to be uploaded, but none was captured")
	}

	refManifest, ok := capturedManifest.(referrerManifest)
	if !ok {
		t.Fatalf("Expected referrerManifest, got %T", capturedManifest)
	}

	if len(refManifest.Layers) == 0 {
		t.Fatal("Expected at least one layer in manifest")
	}

	// Verify per-layer annotations are preserved (this is the bug fix)
	layerAnnotations := refManifest.Layers[0].Annotations
	if layerAnnotations == nil {
		t.Fatal("Expected layer annotations to be preserved, got nil")
	}

	expectedKeys := []string{
		"dev.sigstore.cosign/certificate",
		"dev.sigstore.cosign/chain",
		"predicateType",
	}
	for _, key := range expectedKeys {
		if _, exists := layerAnnotations[key]; !exists {
			t.Errorf("Expected layer annotation %q to be present", key)
		}
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

func TestWriteSignaturesExperimentalOCI(t *testing.T) {
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

	// Create a test signed entity with signatures
	i, err := random.Image(300, 1)
	if err != nil {
		t.Fatalf("random.Image() = %v", err)
	}
	si := signed.Image(i)

	// Add a signature
	sig, err := cosignstatic.NewSignature(nil, "test-sig")
	if err != nil {
		t.Fatalf("static.NewSignature() = %v", err)
	}
	si, err = mutate.AttachSignatureToImage(si, sig)
	if err != nil {
		t.Fatalf("AttachSignatureToImage() = %v", err)
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

	err = WriteSignaturesExperimentalOCI(digest, si)
	if err != nil {
		t.Fatalf("WriteSignaturesExperimentalOCI() = %v", err)
	}

	// Verify that a manifest was uploaded
	if capturedManifest == nil {
		t.Fatal("Expected manifest to be uploaded, but none was captured")
	}

	// Verify it's a referrerManifest (not a taggableManifest)
	refManifest, ok := capturedManifest.(referrerManifest)
	if !ok {
		t.Fatalf("Expected referrerManifest, got %T", capturedManifest)
	}

	// Verify the top-level artifactType is set to the cosign signature type
	const wantArtifactType = "application/vnd.dev.cosign.artifact.sig.v1+json"
	if refManifest.ArtifactType != wantArtifactType {
		t.Errorf("ArtifactType = %q, want %q", refManifest.ArtifactType, wantArtifactType)
	}

	// Verify the subject is set
	if refManifest.Subject == nil {
		t.Error("Expected Subject to be set")
	}

	// Verify the manifest JSON serialization includes the top-level artifactType field
	manifestBytes, err := refManifest.RawManifest()
	if err != nil {
		t.Fatalf("RawManifest() = %v", err)
	}
	if !strings.Contains(string(manifestBytes), `"artifactType"`) {
		t.Errorf("Expected manifest JSON to contain artifactType field, got: %s", string(manifestBytes))
	}
}

// stubSignedImageIndex is a minimal oci.SignedImageIndex whose SignedImage
// and SignedImageIndex accessors report no nested image or index, so
// WriteSignedImageIndexImages falls straight through to scanning the
// on-disk layout for referrer manifests. The methods below that aren't
// exercised by that code path are unimplemented on purpose.
type stubSignedImageIndex struct{}

func (*stubSignedImageIndex) MediaType() (types.MediaType, error) {
	panic("not implemented")
}

func (*stubSignedImageIndex) Digest() (v1.Hash, error) {
	panic("not implemented")
}

func (*stubSignedImageIndex) Size() (int64, error) {
	panic("not implemented")
}

func (*stubSignedImageIndex) IndexManifest() (*v1.IndexManifest, error) {
	panic("not implemented")
}

func (*stubSignedImageIndex) RawManifest() ([]byte, error) {
	panic("not implemented")
}

func (*stubSignedImageIndex) Image(v1.Hash) (v1.Image, error) {
	panic("not implemented")
}

func (*stubSignedImageIndex) ImageIndex(v1.Hash) (v1.ImageIndex, error) {
	panic("not implemented")
}

func (*stubSignedImageIndex) Attachment(string) (oci.File, error) {
	panic("not implemented")
}

func (*stubSignedImageIndex) SignedImage(v1.Hash) (oci.SignedImage, error) {
	return nil, nil
}

func (*stubSignedImageIndex) SignedImageIndex(v1.Hash) (oci.SignedImageIndex, error) {
	return nil, nil
}

func (*stubSignedImageIndex) Signatures() (oci.Signatures, error) {
	return nil, nil
}

func (*stubSignedImageIndex) Attestations() (oci.Signatures, error) {
	return nil, nil
}

var _ oci.SignedImageIndex = (*stubSignedImageIndex)(nil)

// TestWriteSignedImageIndexImagesBundleLayerBeforeManifest is a regression
// test for https://github.com/sigstore/cosign/issues/5030: `cosign load`
// PUT the bundle referrer manifest before uploading the bundle layer blob
// it references, which registries that enforce blob-before-manifest
// ordering (e.g. AWS ECR) reject with BLOB_UPLOAD_UNKNOWN.
func TestWriteSignedImageIndexImagesBundleLayerBeforeManifest(t *testing.T) {
	origPut := remotePut
	origWriteLayer := remoteWriteLayer
	t.Cleanup(func() {
		remotePut = origPut
		remoteWriteLayer = origWriteLayer
	})

	// writeEmptyConfigLayer also goes through remoteWriteLayer, so tell the
	// bundle layer apart from the empty config layer by media type rather
	// than assuming there's only one layer write.
	var order []string
	remoteWriteLayer = func(_ name.Repository, layer v1.Layer, _ ...remote.Option) error {
		mt, err := layer.MediaType()
		if err != nil {
			return err
		}
		if mt == types.MediaType(bundle.BundleV03MediaType) {
			order = append(order, "bundle-layer")
		} else {
			order = append(order, "config-layer")
		}
		return nil
	}
	remotePut = func(_ name.Reference, _ remote.Taggable, _ ...remote.Option) error {
		order = append(order, "manifest")
		return nil
	}

	digestRef := name.MustParseReference(
		"gcr.io/test/image@sha256:1111111111111111111111111111111111111111111111111111111111111111").(name.Digest)
	subjectHash, err := v1.NewHash(digestRef.DigestStr())
	if err != nil {
		t.Fatalf("NewHash() = %v", err)
	}

	tmpDir := t.TempDir()
	blobDir := filepath.Join(tmpDir, "blobs", "sha256")
	if err := os.MkdirAll(blobDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() = %v", err)
	}

	bundleLayerBytes := []byte(`{"bundle":"contents"}`)
	layerHash, _, err := v1.SHA256(bytes.NewReader(bundleLayerBytes))
	if err != nil {
		t.Fatalf("SHA256(layer) = %v", err)
	}
	if err := os.WriteFile(filepath.Join(blobDir, layerHash.Hex), bundleLayerBytes, 0o644); err != nil {
		t.Fatalf("WriteFile(layer) = %v", err)
	}

	bundleManifest := v1.Manifest{
		SchemaVersion: 2,
		MediaType:     types.OCIManifestSchema1,
		Config: v1.Descriptor{
			MediaType: "application/vnd.oci.empty.v1+json",
			Digest:    v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("0", 64)},
			Size:      2,
		},
		Layers: []v1.Descriptor{{
			MediaType: types.MediaType(bundle.BundleV03MediaType),
			Digest:    layerHash,
			Size:      int64(len(bundleLayerBytes)),
		}},
		Subject: &v1.Descriptor{
			MediaType: types.OCIManifestSchema1,
			Digest:    subjectHash,
			Size:      100,
		},
		Annotations: map[string]string{
			BundlePredicateType: "https://test.predicate.type",
		},
	}
	manifestBytes, err := json.Marshal(bundleManifest)
	if err != nil {
		t.Fatalf("json.Marshal(manifest) = %v", err)
	}
	manifestHash, _, err := v1.SHA256(bytes.NewReader(manifestBytes))
	if err != nil {
		t.Fatalf("SHA256(manifest) = %v", err)
	}
	if err := os.WriteFile(filepath.Join(blobDir, manifestHash.Hex), manifestBytes, 0o644); err != nil {
		t.Fatalf("WriteFile(manifest) = %v", err)
	}

	if err := WriteSignedImageIndexImages(digestRef, &stubSignedImageIndex{}, tmpDir); err != nil {
		t.Fatalf("WriteSignedImageIndexImages() = %v", err)
	}

	if len(order) != 3 {
		t.Fatalf("expected the empty config layer, the bundle layer, and the manifest to each be written once, got %v", order)
	}
	bundleLayerIdx := indexOf(order, "bundle-layer")
	manifestIdx := indexOf(order, "manifest")
	if bundleLayerIdx == -1 || manifestIdx == -1 {
		t.Fatalf("expected both a bundle-layer write and a manifest put, got %v", order)
	}
	if bundleLayerIdx > manifestIdx {
		t.Errorf("expected the bundle layer to be uploaded before the manifest, got order %v", order)
	}
}

func indexOf(haystack []string, needle string) int {
	for i, v := range haystack {
		if v == needle {
			return i
		}
	}
	return -1
}
