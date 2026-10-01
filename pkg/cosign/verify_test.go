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

package cosign

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	ggcrlayout "github.com/google/go-containerregistry/pkg/v1/layout"
	gcrMutate "github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/stream"
	"github.com/sigstore/cosign/v3/internal/test"
	"github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/sigstore/cosign/v3/pkg/oci/layout"
	"github.com/sigstore/cosign/v3/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/cosign/v3/pkg/oci/signed"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	"github.com/sigstore/cosign/v3/pkg/types"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockVerifier struct {
	shouldErr bool
}

func (m *mockVerifier) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) { //nolint: revive
	return nil, nil
}

func (m *mockVerifier) VerifySignature(signature, message io.Reader, opts ...signature.VerifyOption) error { //nolint: revive
	if m.shouldErr {
		return errors.New("failure")
	}
	return nil
}

var _ signature.Verifier = (*mockVerifier)(nil)

func TestCompareSigs(t *testing.T) {
	// TODO(nsmith5): Add test cases for invalid signature, missing signature etc
	tests := []struct {
		description string
		b64sig      string
		bundleBody  string
		shouldErr   bool
	}{
		{
			description: "sigs match",
			b64sig:      "MEQCIDO3XHbLovPWK+bk8ItCig2cwlr/8MXbLvz3UFzxMGIMAiA1lqdM9IqqUvCUqzOjufTq3sKU3qSn7R5tPqPz0ddNwQ==",
			bundleBody:  `eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiIzODE1MmQxZGQzMjZhZjQwNWY4OTlkYmNjMmNlMzUwYjVmMTZkNDVkZjdmMjNjNDg4ZjQ4NTBhZmExY2Q4NmQxIn19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FUUNJRE8zWEhiTG92UFdLK2JrOEl0Q2lnMmN3bHIvOE1YYkx2ejNVRnp4TUdJTUFpQTFscWRNOUlxcVV2Q1Vxek9qdWZUcTNzS1UzcVNuN1I1dFBxUHowZGROd1E9PSIsInB1YmxpY0tleSI6eyJjb250ZW50IjoiTFMwdExTMUNSVWRKVGlCUVZVSk1TVU1nUzBWWkxTMHRMUzBLVFVacmQwVjNXVWhMYjFwSmVtb3dRMEZSV1VsTGIxcEplbW93UkVGUlkwUlJaMEZGVUN0RVIyb3ZXWFV4VG5vd01XVjVSV2hVZDNRMlQya3hXV3BGWXdwSloxRldjRlZTTjB0bUwwSm1hVk16Y1ZReFVHd3dkbGh3ZUZwNVMyWkpSMHMyZWxoQ04ybE5aV3RFVTA1M1dHWldPSEpKYUdaMmRrOW5QVDBLTFMwdExTMUZUa1FnVUZWQ1RFbERJRXRGV1MwdExTMHRDZz09In19fX0=`,
		},
		{
			description: "sigs don't match",
			b64sig:      "bm9wZQo=",
			bundleBody:  `eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiIzODE1MmQxZGQzMjZhZjQwNWY4OTlkYmNjMmNlMzUwYjVmMTZkNDVkZjdmMjNjNDg4ZjQ4NTBhZmExY2Q4NmQxIn19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FUUNJRE8zWEhiTG92UFdLK2JrOEl0Q2lnMmN3bHIvOE1YYkx2ejNVRnp4TUdJTUFpQTFscWRNOUlxcVV2Q1Vxek9qdWZUcTNzS1UzcVNuN1I1dFBxUHowZGROd1E9PSIsInB1YmxpY0tleSI6eyJjb250ZW50IjoiTFMwdExTMUNSVWRKVGlCUVZVSk1TVU1nUzBWWkxTMHRMUzBLVFVacmQwVjNXVWhMYjFwSmVtb3dRMEZSV1VsTGIxcEplbW93UkVGUlkwUlJaMEZGVUN0RVIyb3ZXWFV4VG5vd01XVjVSV2hVZDNRMlQya3hXV3BGWXdwSloxRldjRlZTTjB0bUwwSm1hVk16Y1ZReFVHd3dkbGh3ZUZwNVMyWkpSMHMyZWxoQ04ybE5aV3RFVTA1M1dHWldPSEpKYUdaMmRrOW5QVDBLTFMwdExTMUZUa1FnVUZWQ1RFbERJRXRGV1MwdExTMHRDZz09In19fX0=`,
			shouldErr:   true,
		},
	}
	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			sig, err := static.NewSignature([]byte("payload"), test.b64sig)
			if err != nil {
				t.Fatalf("failed to create static signature: %v", err)
			}
			err = compareSigs(test.bundleBody, sig)
			if err == nil && test.shouldErr {
				t.Fatal("test should have errored")
			}
			if err != nil && !test.shouldErr {
				t.Fatal(err)
			}
		})
	}
}

func TestTrustedCertSuccess(t *testing.T) {
	rootCert, rootKey, _ := test.GenerateRootCa()
	subCert, subKey, _ := test.GenerateSubordinateCa(rootCert, rootKey)
	leafCert, _, _ := test.GenerateLeafCert("subject@mail.com", "oidc-issuer", subCert, subKey)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)
	subPool := x509.NewCertPool()
	subPool.AddCert(subCert)

	chains, err := TrustedCert(leafCert, rootPool, subPool)
	if err != nil {
		t.Fatalf("expected no error verifying certificate, got %v", err)
	}
	if len(chains) != 1 {
		t.Fatalf("unexpected number of chains found, expected 1, got %v", len(chains))
	}
	if len(chains[0]) != 3 {
		t.Fatalf("unexpected number of certs in chain, expected 3, got %v", len(chains[0]))
	}
}

func TestTrustedCertSuccessNoIntermediates(t *testing.T) {
	rootCert, rootKey, _ := test.GenerateRootCa()
	leafCert, _, _ := test.GenerateLeafCert("subject@mail.com", "oidc-issuer", rootCert, rootKey)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	_, err := TrustedCert(leafCert, rootPool, nil)
	if err != nil {
		t.Fatalf("expected no error verifying certificate, got %v", err)
	}
}

// Tests that verification succeeds if both a root and subordinate pool are
// present, but a chain is built with only the leaf and root certificates.
func TestTrustedCertSuccessChainFromRoot(t *testing.T) {
	rootCert, rootKey, _ := test.GenerateRootCa()
	leafCert, _, _ := test.GenerateLeafCert("subject@mail.com", "oidc-issuer", rootCert, rootKey)
	subCert, _, _ := test.GenerateSubordinateCa(rootCert, rootKey)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)
	subPool := x509.NewCertPool()
	subPool.AddCert(subCert)

	_, err := TrustedCert(leafCert, rootPool, subPool)
	if err != nil {
		t.Fatalf("expected no error verifying certificate, got %v", err)
	}
}

// calculateLogID generates a SHA-256 hash of the given public key and returns it as a hexadecimal string.
func calculateLogID(t *testing.T, pub crypto.PublicKey) string {
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err, "error marshalling public key")
	digest := sha256.Sum256(pubBytes)
	return hex.EncodeToString(digest[:])
}

func TestHasLocalBundles_V2Signatures(t *testing.T) {
	// Create a signed image with v2-style signatures (no bundle annotation)
	si := createSignedImageWithSignatures(t, false /* withBundle */)
	tmp := t.TempDir()
	if err := layout.WriteSignedImage(tmp, si); err != nil {
		t.Fatalf("WriteSignedImage() = %v", err)
	}

	hasBundles, err := HasLocalBundles(tmp)
	require.NoError(t, err)
	assert.False(t, hasBundles, "expected false for v2 signatures without bundles")
}

func TestHasLocalBundles_V3Bundles(t *testing.T) {
	// Create a layout with v3-style sigstore bundles
	tmp := createV3BundleLayout(t)

	hasBundles, err := HasLocalBundles(tmp)
	require.NoError(t, err)
	assert.True(t, hasBundles, "expected true for v3 signatures with bundles")
}

func TestHasLocalBundles_NoSignatures(t *testing.T) {
	// Create an image without any signatures
	img, err := random.Image(100, 3)
	require.NoError(t, err)
	si := signed.Image(img)
	tmp := t.TempDir()
	if err := layout.WriteSignedImage(tmp, si); err != nil {
		t.Fatalf("WriteSignedImage() = %v", err)
	}

	hasBundles, err := HasLocalBundles(tmp)
	require.NoError(t, err)
	assert.False(t, hasBundles, "expected false for image without signatures")
}

func TestHasLocalBundles_MixedFormats(t *testing.T) {
	// Create a layout with v3-style sigstore bundles (mixed = has bundles)
	tmp := createV3BundleLayout(t)

	hasBundles, err := HasLocalBundles(tmp)
	require.NoError(t, err)
	assert.True(t, hasBundles, "expected true when at least one v3 bundle exists")
}

func TestHasLocalBundles_InvalidPath(t *testing.T) {
	_, err := HasLocalBundles("/nonexistent/path")
	require.Error(t, err, "expected error for non-existent path")
}

// createSignedImageWithSignatures creates a test signed image with signatures.
// If withBundle is true, this creates a v3-style layout with sigstore bundle media type.
func createSignedImageWithSignatures(t *testing.T, withBundle bool) oci.SignedImage {
	return createTestSignedImage(t, withBundle, false)
}

func createSignedImageWithAttestations(t *testing.T, withBundle bool) oci.SignedImage {
	return createTestSignedImage(t, withBundle, true)
}

func createTestSignedImage(t *testing.T, withBundle, attestation bool) oci.SignedImage {
	t.Helper()
	img, err := random.Image(100, 3)
	require.NoError(t, err)
	si := signed.Image(img)

	// For v2-style signatures, attach them to the image
	if !withBundle {
		sig, err := static.NewSignature(nil, "test-payload")
		require.NoError(t, err)

		if attestation {
			si, err = mutate.AttachAttestationToImage(si, sig)
		} else {
			si, err = mutate.AttachSignatureToImage(si, sig)
		}
		require.NoError(t, err)
	}
	// For v3-style bundles, they need to be created separately with proper media type
	// The calling test should handle this differently

	return si
}

// createV3BundleLayout creates a layout directory with a v3 sigstore bundle.
// V3 bundles are stored as separate images with layers having the sigstore bundle media type.
func createV3BundleLayout(t *testing.T) string {
	return createV3BundleLayoutWithAnnotations(t, nil)
}

func createV3BundleLayoutWithAnnotations(t *testing.T, annotations map[string]string) string {
	t.Helper()
	tmp := t.TempDir()

	// Create a basic image
	img, err := random.Image(100, 3)
	require.NoError(t, err)
	si := signed.Image(img)

	// Write the signed image with proper annotations
	if err := layout.WriteSignedImage(tmp, si); err != nil {
		t.Fatalf("WriteSignedImage() = %v", err)
	}

	// Get the layout and image index
	p, err := ggcrlayout.FromPath(tmp)
	require.NoError(t, err)

	ii, err := p.ImageIndex()
	require.NoError(t, err)

	manifest, err := ii.IndexManifest()
	require.NoError(t, err)

	// Find the target digest
	var targetDigest v1.Hash
	for _, m := range manifest.Manifests {
		// Look for the image entry
		if m.Annotations["kind"] == "dev.cosignproject.cosign/image" {
			targetDigest = m.Digest
			break
		}
	}
	require.NotEmpty(t, targetDigest.String(), "target digest should be found")

	// Create a bundle layer with the sigstore bundle media type
	bundleContent := []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`)
	bundleLayer := stream.NewLayer(io.NopCloser(bytes.NewReader(bundleContent)),
		stream.WithMediaType("application/vnd.dev.sigstore.bundle.v0.3+json"))

	// Build the referrer manifest
	referrerImg := empty.Image
	referrerImg, err = gcrMutate.AppendLayers(referrerImg, bundleLayer)
	require.NoError(t, err)

	// Append image to materialize stream layers before calling Manifest()
	err = p.AppendImage(referrerImg)
	require.NoError(t, err)

	// Get the manifest and add Subject field
	referrerManifest, err := referrerImg.Manifest()
	require.NoError(t, err)

	// Set Subject to point to target image
	referrerManifest.Subject = &v1.Descriptor{
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Digest:    targetDigest,
		Size:      0,
	}
	referrerManifest.Annotations = annotations

	// Write the referrer manifest to blobs/sha256
	blobsDir := tmp + "/blobs/sha256"
	err = os.MkdirAll(blobsDir, 0755)
	require.NoError(t, err)

	manifestBytes, err := json.Marshal(referrerManifest)
	require.NoError(t, err)

	manifestHash := v1.Hash{Algorithm: "sha256", Hex: fmt.Sprintf("%x", sha256.Sum256(manifestBytes))}
	manifestPath := filepath.Join(blobsDir, manifestHash.Hex)
	err = os.WriteFile(manifestPath, manifestBytes, 0644)
	require.NoError(t, err)

	return tmp
}

func TestHasLocalAttestationBundles_V2Attestations(t *testing.T) {
	si := createSignedImageWithAttestations(t, false)
	tmp := t.TempDir()
	if err := layout.WriteSignedImage(tmp, si); err != nil {
		t.Fatalf("WriteSignedImage() = %v", err)
	}

	hasBundles, err := HasLocalAttestationBundles(tmp)
	require.NoError(t, err)
	assert.False(t, hasBundles, "expected false for v2 attestations without bundles")
}

func TestHasLocalAttestationBundles_V3Bundles(t *testing.T) {
	// V3 bundles are the same for signatures and attestations
	tmp := createV3BundleLayout(t)

	hasBundles, err := HasLocalAttestationBundles(tmp)
	require.NoError(t, err)
	assert.True(t, hasBundles, "expected true for v3 attestations with bundles")
}

func TestHasLocalAttestationBundles_SignatureBundleOnly(t *testing.T) {
	tmp := createV3BundleLayoutWithAnnotations(t, map[string]string{
		ociremote.BundlePredicateType: types.CosignSignPredicateType,
	})

	hasBundles, err := HasLocalAttestationBundles(tmp)
	require.NoError(t, err)
	assert.False(t, hasBundles, "expected false when layout only contains signature bundles")
}

func TestHasLocalSigstoreBundles_OCIReferrers(t *testing.T) {
	// Create a layout with OCI referrers pointing to target image with bundle layers
	tmp := t.TempDir()

	// Create base image
	img, err := random.Image(100, 3)
	require.NoError(t, err)
	si := signed.Image(img)

	// Write the signed image with proper annotations
	if err := layout.WriteSignedImage(tmp, si); err != nil {
		t.Fatalf("WriteSignedImage() = %v", err)
	}

	// Get the layout and image index
	p, err := ggcrlayout.FromPath(tmp)
	require.NoError(t, err)

	ii, err := p.ImageIndex()
	require.NoError(t, err)

	manifest, err := ii.IndexManifest()
	require.NoError(t, err)

	// Find the target digest
	var targetDigest v1.Hash
	for _, m := range manifest.Manifests {
		// Look for the image entry
		if m.Annotations["kind"] == "dev.cosignproject.cosign/image" {
			targetDigest = m.Digest
			break
		}
	}
	require.NotEmpty(t, targetDigest.String(), "target digest should be found")

	// Create a referrer manifest with Subject pointing to target
	bundleContent := []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`)
	bundleLayer := stream.NewLayer(io.NopCloser(bytes.NewReader(bundleContent)),
		stream.WithMediaType("application/vnd.dev.sigstore.bundle.v0.3+json"))

	// Build the referrer manifest
	referrerImg := empty.Image
	referrerImg, err = gcrMutate.AppendLayers(referrerImg, bundleLayer)
	require.NoError(t, err)

	// Append image to materialize stream layers before calling Manifest()
	err = p.AppendImage(referrerImg)
	require.NoError(t, err)

	// Get the manifest and add Subject field
	referrerManifest, err := referrerImg.Manifest()
	require.NoError(t, err)

	// Set Subject to point to target image
	referrerManifest.Subject = &v1.Descriptor{
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Digest:    targetDigest,
		Size:      0,
	}

	// Write the referrer manifest to blobs/sha256
	blobsDir := tmp + "/blobs/sha256"
	err = os.MkdirAll(blobsDir, 0755)
	require.NoError(t, err)

	manifestBytes, err := json.Marshal(referrerManifest)
	require.NoError(t, err)

	manifestHash := v1.Hash{Algorithm: "sha256", Hex: fmt.Sprintf("%x", sha256.Sum256(manifestBytes))}
	manifestPath := filepath.Join(blobsDir, manifestHash.Hex)
	err = os.WriteFile(manifestPath, manifestBytes, 0644)
	require.NoError(t, err)

	// Test that hasLocalSigstoreBundles detects the referrer
	hasBundles, err := hasLocalSigstoreBundles(tmp)
	require.NoError(t, err)
	assert.True(t, hasBundles, "expected true for OCI referrers with bundle layers")
}

func TestHasLocalSigstoreBundles_ImageIndex(t *testing.T) {
	// Create a layout with an image index and OCI referrers pointing to it with bundle layers
	tmp := t.TempDir()

	// Create base image index
	idx, err := random.Index(100, 3, 2)
	require.NoError(t, err)
	sii := signed.ImageIndex(idx)

	// Write the signed image index with proper annotations
	if err := layout.WriteSignedImageIndex(tmp, sii); err != nil {
		t.Fatalf("WriteSignedImageIndex() = %v", err)
	}

	// Get the layout and root image index
	p, err := ggcrlayout.FromPath(tmp)
	require.NoError(t, err)

	ii, err := p.ImageIndex()
	require.NoError(t, err)

	manifest, err := ii.IndexManifest()
	require.NoError(t, err)

	// Find the target digest for the imageIndex entry
	var targetDigest v1.Hash
	for _, m := range manifest.Manifests {
		if m.Annotations["kind"] == "dev.cosignproject.cosign/imageIndex" {
			targetDigest = m.Digest
			break
		}
	}
	require.NotEmpty(t, targetDigest.String(), "target digest should be found for imageIndex")

	// Create a bundle layer with the sigstore bundle media type
	bundleContent := []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`)
	bundleLayer := stream.NewLayer(io.NopCloser(bytes.NewReader(bundleContent)),
		stream.WithMediaType("application/vnd.dev.sigstore.bundle.v0.3+json"))

	// Build the referrer manifest
	referrerImg := empty.Image
	referrerImg, err = gcrMutate.AppendLayers(referrerImg, bundleLayer)
	require.NoError(t, err)

	// Append image to materialize stream layers before calling Manifest()
	err = p.AppendImage(referrerImg)
	require.NoError(t, err)

	// Get the manifest and add Subject field pointing to the image index
	referrerManifest, err := referrerImg.Manifest()
	require.NoError(t, err)

	referrerManifest.Subject = &v1.Descriptor{
		MediaType: "application/vnd.oci.image.index.v1+json",
		Digest:    targetDigest,
		Size:      0,
	}

	// Write the referrer manifest to blobs/sha256
	blobsDir := tmp + "/blobs/sha256"
	err = os.MkdirAll(blobsDir, 0755)
	require.NoError(t, err)

	manifestBytes, err := json.Marshal(referrerManifest)
	require.NoError(t, err)

	manifestHash := v1.Hash{Algorithm: "sha256", Hex: fmt.Sprintf("%x", sha256.Sum256(manifestBytes))}
	manifestPath := filepath.Join(blobsDir, manifestHash.Hex)
	err = os.WriteFile(manifestPath, manifestBytes, 0644)
	require.NoError(t, err)

	// Test that hasLocalSigstoreBundles detects the referrer
	hasBundles, err := hasLocalSigstoreBundles(tmp)
	require.NoError(t, err)
	assert.True(t, hasBundles, "expected true for OCI referrers with bundle layers")
}

func TestHasLocalSigstoreBundles_NoBlobsDir(t *testing.T) {
	// Create a layout without blobs/sha256 directory
	tmp := t.TempDir()

	// Create base image
	img, err := random.Image(100, 3)
	require.NoError(t, err)
	si := signed.Image(img)

	if err := layout.WriteSignedImage(tmp, si); err != nil {
		t.Fatalf("WriteSignedImage() = %v", err)
	}

	// Remove blobs directory to simulate missing directory
	blobsDir := tmp + "/blobs/sha256"
	err = os.RemoveAll(blobsDir)
	require.NoError(t, err)

	// Should return false without error
	hasBundles, err := hasLocalSigstoreBundles(tmp)
	require.NoError(t, err)
	assert.False(t, hasBundles, "expected false when blobs/sha256 directory missing")
}

func TestHasLocalSigstoreBundles_ReferrerDifferentSubject(t *testing.T) {
	// Create a layout with a referrer pointing to a different subject
	tmp := t.TempDir()

	// Create base image
	img, err := random.Image(100, 3)
	require.NoError(t, err)
	si := signed.Image(img)

	if err := layout.WriteSignedImage(tmp, si); err != nil {
		t.Fatalf("WriteSignedImage() = %v", err)
	}

	// Create a referrer manifest with Subject pointing to different digest
	bundleContent := []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`)

	// Calculate the bundle layer descriptor
	bundleDigest := v1.Hash{Algorithm: "sha256", Hex: fmt.Sprintf("%x", sha256.Sum256(bundleContent))}
	bundleDescriptor := v1.Descriptor{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		Digest:    bundleDigest,
		Size:      int64(len(bundleContent)),
	}

	// Create a minimal config
	configContent := []byte("{}")
	configDigest := v1.Hash{Algorithm: "sha256", Hex: fmt.Sprintf("%x", sha256.Sum256(configContent))}
	configDescriptor := v1.Descriptor{
		MediaType: "application/vnd.oci.image.config.v1+json",
		Digest:    configDigest,
		Size:      int64(len(configContent)),
	}

	// Set Subject to a different digest
	differentDigest := v1.Hash{Algorithm: "sha256", Hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}

	// Build the manifest structure directly
	referrerManifest := &v1.Manifest{
		SchemaVersion: 2,
		MediaType:     "application/vnd.oci.image.manifest.v1+json",
		Config:        configDescriptor,
		Layers:        []v1.Descriptor{bundleDescriptor},
		Subject: &v1.Descriptor{
			MediaType: "application/vnd.oci.image.manifest.v1+json",
			Digest:    differentDigest,
			Size:      0,
		},
	}

	// Write the referrer manifest to blobs/sha256
	blobsDir := tmp + "/blobs/sha256"

	manifestBytes, err := json.Marshal(referrerManifest)
	require.NoError(t, err)

	manifestHash := v1.Hash{Algorithm: "sha256", Hex: fmt.Sprintf("%x", sha256.Sum256(manifestBytes))}
	manifestPath := filepath.Join(blobsDir, manifestHash.Hex)
	err = os.WriteFile(manifestPath, manifestBytes, 0644)
	require.NoError(t, err)

	// Should return false since referrer points to different subject
	hasBundles, err := hasLocalSigstoreBundles(tmp)
	require.NoError(t, err)
	assert.False(t, hasBundles, "expected false when referrer points to different subject")
}

func TestHasLocalSigstoreBundles_EmptyBlobsDir(t *testing.T) {
	// Create a layout with empty blobs/sha256 directory
	tmp := t.TempDir()

	// Create base image
	img, err := random.Image(100, 3)
	require.NoError(t, err)
	si := signed.Image(img)

	if err := layout.WriteSignedImage(tmp, si); err != nil {
		t.Fatalf("WriteSignedImage() = %v", err)
	}

	// Clear the blobs directory (but keep it existing)
	blobsDir := tmp + "/blobs/sha256"
	entries, err := os.ReadDir(blobsDir)
	require.NoError(t, err)

	for _, entry := range entries {
		err = os.Remove(filepath.Join(blobsDir, entry.Name()))
		require.NoError(t, err)
	}

	// Should return false without error
	hasBundles, err := hasLocalSigstoreBundles(tmp)
	require.NoError(t, err)
	assert.False(t, hasBundles, "expected false for empty blobs directory")
}

func TestGetLocalBundles_MissingBlobsDir(t *testing.T) {
	tmp := t.TempDir()

	// Create base image
	img, err := random.Image(100, 3)
	require.NoError(t, err)
	si := signed.Image(img)

	if err := layout.WriteSignedImage(tmp, si); err != nil {
		t.Fatalf("WriteSignedImage() = %v", err)
	}

	// Remove blobs directory
	blobsDir := tmp + "/blobs/sha256"
	err = os.RemoveAll(blobsDir)
	require.NoError(t, err)

	bundles, hash, err := GetLocalBundles(tmp)
	assert.Error(t, err, "expected ErrNoMatchingAttestations when no bundles exist")
	assert.Nil(t, hash)
	assert.Nil(t, bundles)
	var noMatchErr *ErrNoMatchingAttestations
	assert.ErrorAs(t, err, &noMatchErr, "expected ErrNoMatchingAttestations")
}

func TestGetLocalBundles_ZeroBundles(t *testing.T) {
	tmp := t.TempDir()

	// Create base image without any bundles
	img, err := random.Image(100, 3)
	require.NoError(t, err)
	si := signed.Image(img)

	if err := layout.WriteSignedImage(tmp, si); err != nil {
		t.Fatalf("WriteSignedImage() = %v", err)
	}

	bundles, hash, err := GetLocalBundles(tmp)
	assert.Error(t, err, "expected error when zero bundles exist")
	assert.Nil(t, hash)
	assert.Nil(t, bundles)
	var noMatchErr *ErrNoMatchingAttestations
	assert.ErrorAs(t, err, &noMatchErr, "expected ErrNoMatchingAttestations")
}

func TestGetLocalBundles_InvalidPath(t *testing.T) {
	bundles, hash, err := GetLocalBundles("/nonexistent/path")
	require.Error(t, err)
	assert.Nil(t, hash)
	assert.Nil(t, bundles)
}
func TestBundleHash(t *testing.T) {
	sv, _, err := signature.NewECDSASignerVerifier(elliptic.P256(), rand.Reader, crypto.SHA256)
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}
	pemBytes, _ := cryptoutils.MarshalPublicKeyToPEM(sv.Public())
	b64key := base64.StdEncoding.EncodeToString(pemBytes)

	payload := []byte{1, 2, 3, 4}
	digest := sha256.Sum256(payload)
	value := hex.EncodeToString(digest[:])
	sig, err := sv.SignMessage(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	b64sig := base64.StdEncoding.EncodeToString(sig)
	hash := fmt.Sprintf(`{"algorithm":"sha256","value":%q}`, value)

	tests := []struct {
		name string
		body string
	}{{
		name: "dsse v0.0.1",
		body: fmt.Sprintf(`{"apiVersion":"0.0.1","kind":"dsse","spec":{"envelopeHash":%s,"payloadHash":%s,"signatures":[{"signature":%q,"verifier":%q}]}}`,
			hash, hash, b64sig, b64key),
	}, {
		name: "hashedrekord v0.0.1",
		body: fmt.Sprintf(`{"apiVersion":"0.0.1","kind":"hashedrekord","spec":{"data":{"hash":%s},"signature":{"content":%q,"publicKey":{"content":%q}}}}`,
			hash, b64sig, b64key),
	}, {
		name: "intoto v0.0.1",
		body: fmt.Sprintf(`{"apiVersion":"0.0.1","kind":"intoto","spec":{"content":{"hash":%s,"payloadHash":%s},"publicKey":%q}}`,
			hash, hash, b64key),
	}, {
		name: "intoto v0.0.2",
		body: fmt.Sprintf(`{"apiVersion":"0.0.2","kind":"intoto","spec":{"content":{"envelope":{"payloadType":"application/vnd.in-toto+json","payload":"","signatures":[{"publicKey":%q,"sig":%q}]},"hash":%s}}}`,
			b64key, b64sig, hash),
	}, {
		name: "rekord v0.0.1",
		body: fmt.Sprintf(`{"apiVersion":"0.0.1","kind":"rekord","spec":{"data":{"hash":%s},"signature":{"format":"x509","content":%q,"publicKey":{"content":%q}}}}`,
			hash, b64sig, b64key),
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alg, val, err := bundleHash(base64.StdEncoding.EncodeToString([]byte(tt.body)), "")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if alg != "sha256" || val != value {
				t.Errorf("got %s:%s, want sha256:%s", alg, val, value)
			}
		})
	}
}

func TestBundleHashWithMissingHash(t *testing.T) {
	sv, _, err := signature.NewECDSASignerVerifier(elliptic.P256(), rand.Reader, crypto.SHA256)
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}
	pemBytes, _ := cryptoutils.MarshalPublicKeyToPEM(sv.Public())
	b64key := base64.StdEncoding.EncodeToString(pemBytes)
	value := strings.Repeat("0", 64)
	payloadHash := fmt.Sprintf(`{"algorithm":"sha256","value":%q}`, value)

	rekord := func(hash string) string {
		return fmt.Sprintf(`{"apiVersion":"0.0.1","kind":"rekord","spec":{"data":{"content":"YQ=="%s},"signature":{"format":"x509","content":"YQ==","publicKey":{"content":%q}}}}`,
			hash, b64key)
	}
	intotoV002 := func(hash string) string {
		return fmt.Sprintf(`{"apiVersion":"0.0.2","kind":"intoto","spec":{"content":{"envelope":{"payloadType":"application/vnd.in-toto+json","payload":"","signatures":[{"publicKey":%q,"sig":"YQ=="}]}%s}}}`,
			b64key, hash)
	}

	// Only rekord v0.0.1 and intoto v0.0.2 accept an entry with no hash, and
	// those reach bundleHash's own check. Rekor rejects every other case
	// before the switch is reached. A hash object missing only its algorithm
	// or value fails Rekor's validation for every entry type, so the
	// hashFields error is covered by TestHashFields instead.
	tests := []struct {
		name    string
		body    string
		wantErr string
	}{{
		name:    "rekord v0.0.1 without data.hash",
		body:    rekord(""),
		wantErr: "no hash found in bundle entry",
	}, {
		name:    "intoto v0.0.2 without content.hash",
		body:    intotoV002(""),
		wantErr: "no hash found in bundle entry",
	}, {
		name: "rekord v0.0.1 without data.hash.value",
		body: rekord(`,"hash":{"algorithm":"sha256"}`),
	}, {
		name: "rekord v0.0.1 without data.hash.algorithm",
		body: rekord(fmt.Sprintf(`,"hash":{"value":%q}`, value)),
	}, {
		name: "intoto v0.0.2 without content.hash.value",
		body: intotoV002(`,"hash":{"algorithm":"sha256"}`),
	}, {
		name: "intoto v0.0.2 without content.hash.algorithm",
		body: intotoV002(fmt.Sprintf(`,"hash":{"value":%q}`, value)),
	}, {
		name: "dsse v0.0.1 without envelopeHash",
		body: fmt.Sprintf(`{"apiVersion":"0.0.1","kind":"dsse","spec":{"payloadHash":%s,"signatures":[{"signature":"YQ==","verifier":%q}]}}`,
			payloadHash, b64key),
	}, {
		name: "hashedrekord v0.0.1 without data.hash",
		body: fmt.Sprintf(`{"apiVersion":"0.0.1","kind":"hashedrekord","spec":{"data":{},"signature":{"content":"YQ==","publicKey":{"content":%q}}}}`,
			b64key),
	}, {
		name: "intoto v0.0.1 without content.hash",
		body: fmt.Sprintf(`{"apiVersion":"0.0.1","kind":"intoto","spec":{"content":{"payloadHash":%s},"publicKey":%q}}`,
			payloadHash, b64key),
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := bundleHash(base64.StdEncoding.EncodeToString([]byte(tt.body)), "")
			if err == nil {
				t.Fatal("expected an error, got none")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("wanted %q, got: %v", tt.wantErr, err)
			}
		})
	}
}

func TestHashFields(t *testing.T) {
	algorithm, value := "sha256", strings.Repeat("0", 64)
	tests := []struct {
		name      string
		algorithm *string
		value     *string
		wantErr   bool
	}{
		{name: "both set", algorithm: &algorithm, value: &value},
		{name: "missing algorithm", value: &value, wantErr: true},
		{name: "missing value", algorithm: &algorithm, wantErr: true},
		{name: "missing both", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alg, val, err := hashFields(tt.algorithm, tt.value)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if alg != algorithm || val != value {
				t.Errorf("got %s:%s, want %s:%s", alg, val, algorithm, value)
			}
		})
	}
}

