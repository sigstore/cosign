// Copyright 2025 The Sigstore Authors.
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
	"context"
	_ "embed"
	"fmt"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"

	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
)

//go:embed testdata/oci-attestation.sigstore.json
var testAttestation []byte

//go:embed testdata/trusted_root_pgi.json
var testTrustedRootPGI []byte

func TestGetBundles_Empty(t *testing.T) {
	r := registry.New(registry.WithReferrersSupport(true))
	s := httptest.NewServer(r)
	defer s.Close()

	u, err := url.Parse(s.URL)
	assert.NoError(t, err)

	ref, err := name.ParseReference(fmt.Sprintf("%s/repo:tag", u.Host))
	assert.NoError(t, err)

	// If tag doesn't exist, should return ErrImageTagNotFound
	bundles, hash, err := getBundles(context.Background(), ref, &CheckOpts{})
	imgTagNotFound := &ErrImageTagNotFound{}
	assert.ErrorAs(t, err, &imgTagNotFound)
	assert.Len(t, bundles, 0)
	assert.Nil(t, hash)

	// Write an image
	img, err := random.Image(10, 10)
	assert.NoError(t, err)
	assert.NoError(t, remote.Write(ref, img))

	// Check that no matching attestation error is returned
	bundles, hash, err = getBundles(context.Background(), ref, &CheckOpts{})
	var noMatchErr *ErrNoMatchingAttestations
	assert.ErrorAs(t, err, &noMatchErr)
	assert.Len(t, bundles, 0)
	assert.Nil(t, hash)

	// Get digest from tag
	desc, err := remote.Head(ref)
	assert.NoError(t, err)
	digestRef := ref.Context().Digest(desc.Digest.String())

	// Write invalid attestation
	err = ociremote.WriteAttestationNewBundleFormat(digestRef, []byte("invalid"), "foo/bar")
	assert.NoError(t, err)

	// Should still return no matching attestation error, as it failed to parse the bundle
	bundles, hash, err = getBundles(context.Background(), ref, &CheckOpts{})
	assert.ErrorAs(t, err, &noMatchErr)
	assert.Len(t, bundles, 0)
	assert.Nil(t, hash)
}

func TestGetBundles_Valid(t *testing.T) {
	r := registry.New(registry.WithReferrersSupport(true))
	s := httptest.NewServer(r)
	defer s.Close()

	u, err := url.Parse(s.URL)
	assert.NoError(t, err)

	ref, err := name.ParseReference(fmt.Sprintf("%s/repo:tag", u.Host))
	assert.NoError(t, err)

	// Test data uses empty image
	assert.NoError(t, remote.Write(ref, empty.Image))

	// Get digest from tag
	desc, err := remote.Head(ref)
	assert.NoError(t, err)
	digestRef := ref.Context().Digest(desc.Digest.String())

	// Write valid test attestation
	err = ociremote.WriteAttestationNewBundleFormat(digestRef, testAttestation, "https://cosign.sigstore.dev/attestation/v1")
	assert.NoError(t, err)

	// Retrieve the attestation
	bundles, hash, err := getBundles(context.Background(), ref, &CheckOpts{})
	assert.NoError(t, err)
	assert.Len(t, bundles, 1)
	assert.NotNil(t, hash)

	// Compare the output to the test data
	expected := sgbundle.Bundle{}
	err = expected.UnmarshalJSON(testAttestation)
	assert.NoError(t, err)
	if !proto.Equal(bundles[0].Bundle, &expected) {
		t.Errorf("got %v, want %v", bundles[0].Bundle, &expected)
	}
}

// TODO: This test is getting long and maybe should be refactored into a
// table-based test to exercise more permutations.
func TestVerifyImageAttestationsSigstoreBundle(t *testing.T) {
	r := registry.New(registry.WithReferrersSupport(true))
	s := httptest.NewServer(r)
	defer s.Close()

	u, err := url.Parse(s.URL)
	assert.NoError(t, err)

	ref, err := name.ParseReference(fmt.Sprintf("%s/repo:tag", u.Host))
	assert.NoError(t, err)

	ref2, err := name.ParseReference(fmt.Sprintf("%s/repo:tag2", u.Host))
	assert.NoError(t, err)

	// Parse test root
	trustedRoot, err := root.NewTrustedRootFromJSON(testTrustedRootPGI)
	assert.NoError(t, err)

	// Test data uses empty image
	assert.NoError(t, remote.Write(ref, empty.Image))

	// Also write a second image to test that we only verify the correct image
	randomImage, err := random.Image(10, 10)
	assert.NoError(t, err)
	assert.NoError(t, remote.Write(ref2, randomImage))

	// Attempt to verify non-existent attestation
	atts, bundleVerified, err := VerifyImageAttestations(context.Background(), ref, &CheckOpts{
		TrustedMaterial: trustedRoot,
		NewBundleFormat: true,
		Identities: []Identity{
			{
				IssuerRegExp:  ".*",
				SubjectRegExp: ".*",
			},
		},
	})
	var errNoMatchingAttestations *ErrNoMatchingAttestations
	assert.ErrorAs(t, err, &errNoMatchingAttestations)
	assert.False(t, bundleVerified)
	assert.Len(t, atts, 0)

	// Get digest from tag
	desc, err := remote.Head(ref)
	assert.NoError(t, err)
	digestRef := ref.Context().Digest(desc.Digest.String())

	// Write valid test attestation
	err = ociremote.WriteAttestationNewBundleFormat(digestRef, testAttestation, "https://cosign.sigstore.dev/attestation/v1")
	assert.NoError(t, err)

	// Verify the attestation
	atts, bundleVerified, err = VerifyImageAttestations(context.Background(), ref, &CheckOpts{
		TrustedMaterial: trustedRoot,
		NewBundleFormat: true,
		Identities: []Identity{
			{
				IssuerRegExp:  ".*",
				SubjectRegExp: ".*",
			},
		},
	})
	assert.NoError(t, err)
	assert.True(t, bundleVerified)
	assert.Len(t, atts, 1)

	// Wrong identity should not verify
	atts, bundleVerified, err = VerifyImageAttestations(context.Background(), ref, &CheckOpts{
		TrustedMaterial: trustedRoot,
		NewBundleFormat: true,
		Identities: []Identity{
			{
				IssuerRegExp:  ".*",
				SubjectRegExp: "wrong",
			},
		},
	})
	assert.ErrorAs(t, err, &errNoMatchingAttestations)
	assert.False(t, bundleVerified)
	assert.Len(t, atts, 0)

	// Add same attestation to different image with different digest to test that we only verify the correct image
	// Get digest from tag
	desc, err = remote.Head(ref2)
	assert.NoError(t, err)
	digestRef = ref2.Context().Digest(desc.Digest.String())

	// Write valid test attestation
	err = ociremote.WriteAttestationNewBundleFormat(digestRef, testAttestation, "https://cosign.sigstore.dev/attestation/v1")
	assert.NoError(t, err)

	// Verify the attestation
	atts, bundleVerified, err = VerifyImageAttestations(context.Background(), ref2, &CheckOpts{
		TrustedMaterial: trustedRoot,
		NewBundleFormat: true,
		Identities: []Identity{
			{
				IssuerRegExp:  ".*",
				SubjectRegExp: ".*",
			},
		},
	})
	assert.Error(t, err)
	assert.ErrorAs(t, err, &errNoMatchingAttestations)
	// TODO: This error message comes from sigstore-go. We may want to update the upstream with a sentinal error type.
	assert.ErrorContains(t, err, "provided artifact digest does not match any digest in statement")
	assert.False(t, bundleVerified)
	assert.Len(t, atts, 0)
}
