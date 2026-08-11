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
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/timestamp"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	ggcrlayout "github.com/google/go-containerregistry/pkg/v1/layout"
	gcrMutate "github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/stream"
	tsaMock "github.com/sigstore/cosign/v3/internal/pkg/cosign/tsa/mock"
	"github.com/sigstore/cosign/v3/internal/test"
	"github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/sigstore/cosign/v3/pkg/oci/layout"
	"github.com/sigstore/cosign/v3/pkg/oci/mutate"
	"github.com/sigstore/cosign/v3/pkg/oci/signed"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	"github.com/sigstore/sigstore-go/pkg/root"
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

func appendSlices(slices [][]byte) []byte {
	totalLen := 0
	for _, s := range slices {
		totalLen += len(s)
	}
	tmp := make([]byte, 0, totalLen)
	for _, s := range slices {
		tmp = append(tmp, s...)
	}
	return tmp
}

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

func TestVerifyRFC3161Timestamp(t *testing.T) {
	// generate signed artifact
	rootCert, rootKey, _ := test.GenerateRootCa()
	leafCert, privKey, _ := test.GenerateLeafCert("subject", "oidc-issuer", rootCert, rootKey)
	pemRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Raw})
	pemLeaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Raw})
	payload := []byte{1, 2, 3, 4}
	h := sha256.Sum256(payload)
	signature, _ := privKey.Sign(rand.Reader, h[:], crypto.SHA256)

	client, err := tsaMock.NewTSAClient((tsaMock.TSAClientOptions{Time: time.Now()}))
	if err != nil {
		t.Fatal(err)
	}

	tsBytes, err := getTimestampedSignature(signature, client)
	if err != nil {
		t.Fatalf("unexpected error creating timestamp: %v", err)
	}
	rfc3161TS := bundle.RFC3161Timestamp{SignedRFC3161Timestamp: tsBytes}

	certChainPEM, err := cryptoutils.MarshalCertificatesToPEM(client.CertChain)
	if err != nil {
		t.Fatalf("unexpected error marshalling cert chain: %v", err)
	}

	leaves, intermediates, roots, err := splitPEMCertificateChain(certChainPEM)
	if err != nil {
		t.Fatal("error splitting response into certificate chain")
	}

	ociSig, _ := static.NewSignature(payload,
		base64.StdEncoding.EncodeToString(signature),
		static.WithCertChain(pemLeaf, appendSlices([][]byte{pemRoot})),
		static.WithRFC3161Timestamp(&rfc3161TS))

	// success, signing over signature
	ts, err := VerifyRFC3161Timestamp(ociSig, &CheckOpts{
		TSACertificate:              leaves[0],
		TSAIntermediateCertificates: intermediates,
		TSARootCertificates:         roots,
	})
	if err != nil {
		t.Fatalf("unexpected error verifying timestamp with signature: %v", err)
	}
	if err := CheckExpiry(leafCert, nil, ts.Time); err != nil {
		t.Fatalf("unexpected error using time from timestamp to verify certificate: %v", err)
	}

	// success, signing over payload
	tsBytes, err = getTimestampedSignature(payload, client)
	if err != nil {
		t.Fatalf("unexpected error creating timestamp: %v", err)
	}
	rfc3161TS = bundle.RFC3161Timestamp{SignedRFC3161Timestamp: tsBytes}
	ociSig, _ = static.NewSignature(payload,
		"", /*signature*/
		static.WithCertChain(pemLeaf, appendSlices([][]byte{pemRoot})),
		static.WithRFC3161Timestamp(&rfc3161TS))
	_, err = VerifyRFC3161Timestamp(ociSig, &CheckOpts{
		TSACertificate:              leaves[0],
		TSAIntermediateCertificates: intermediates,
		TSARootCertificates:         roots,
	})
	if err != nil {
		t.Fatalf("unexpected error verifying timestamp with payload: %v", err)
	}

	// failure with non-base64 encoded signature
	ociSig, _ = static.NewSignature(payload,
		string(signature),
		static.WithCertChain(pemLeaf, appendSlices([][]byte{pemRoot})),
		static.WithRFC3161Timestamp(&rfc3161TS))
	_, err = VerifyRFC3161Timestamp(ociSig, &CheckOpts{
		TSACertificate:              leaves[0],
		TSAIntermediateCertificates: intermediates,
		TSARootCertificates:         roots,
	})
	if err == nil || !strings.Contains(err.Error(), "base64 data") {
		t.Fatalf("expected error verifying timestamp with raw signature, got: %v", err)
	}

	// failure with mismatched signature
	tsBytes, err = getTimestampedSignature(signature, client)
	if err != nil {
		t.Fatalf("unexpected error creating timestamp: %v", err)
	}
	rfc3161TS = bundle.RFC3161Timestamp{SignedRFC3161Timestamp: tsBytes}
	// regenerate signature
	signature, _ = privKey.Sign(rand.Reader, h[:], crypto.SHA256)
	ociSig, _ = static.NewSignature(payload,
		base64.StdEncoding.EncodeToString(signature),
		static.WithCertChain(pemLeaf, appendSlices([][]byte{pemRoot})),
		static.WithRFC3161Timestamp(&rfc3161TS))
	_, err = VerifyRFC3161Timestamp(ociSig, &CheckOpts{
		TSACertificate:              leaves[0],
		TSAIntermediateCertificates: intermediates,
		TSARootCertificates:         roots,
	})
	if err == nil || !strings.Contains(err.Error(), "hashed messages don't match") {
		t.Fatalf("expected error verifying mismatched signatures, got: %v", err)
	}

	// failure without root certificate
	_, err = VerifyRFC3161Timestamp(ociSig, &CheckOpts{
		TSACertificate:              leaves[0],
		TSAIntermediateCertificates: intermediates,
	})
	if err == nil || !strings.Contains(err.Error(), "no TSA root certificate(s) provided to verify timestamp") {
		t.Fatalf("expected error verifying without a root certificate, got: %v", err)
	}

	// failure with empty TrustedRoot
	emptyTrustedRoot, err := root.NewTrustedRoot(root.TrustedRootMediaType01, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error creating empty trusted root: %v", err)
	}
	_, err = VerifyRFC3161Timestamp(ociSig, &CheckOpts{
		TrustedMaterial: emptyTrustedRoot,
	})
	if err == nil || !strings.Contains(err.Error(), "expected at least one verified timestamp") {
		t.Fatalf("expected error verifying with empty trusted root, got: %v", err)
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

func getTimestampedSignature(sigBytes []byte, tsaClient *tsaMock.TSAClient) ([]byte, error) {
	requestBytes, err := timestamp.CreateRequest(bytes.NewReader(sigBytes), &timestamp.RequestOptions{
		Hash:         crypto.SHA256,
		Certificates: true,
	})
	if err != nil {
		return nil, fmt.Errorf("error creating timestamp request: %w", err)
	}

	return tsaClient.GetTimestampResponse(requestBytes)
}
