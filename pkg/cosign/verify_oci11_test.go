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
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/sigstore/cosign/v3/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/cosign/v3/pkg/oci/signed"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	"github.com/sigstore/cosign/v3/pkg/types"
	"github.com/sigstore/sigstore/pkg/signature"
	sigdsse "github.com/sigstore/sigstore/pkg/signature/dsse"
)

func newDSSEAttestationEntity(t *testing.T, digestRef name.Digest, sv signature.SignerVerifier, rOpts []remote.Option) oci.SignedEntity {
	t.Helper()

	stmt, err := json.Marshal(in_toto.Statement{
		StatementHeader: in_toto.StatementHeader{
			Type:          in_toto.StatementInTotoV01,
			PredicateType: "cosign.sigstore.dev/attestation/v1",
			Subject: []in_toto.Subject{{
				Name:   digestRef.Repository.Name(),
				Digest: map[string]string{"sha256": digestRef.DigestStr()[len("sha256:"):]},
			}},
		},
		Predicate: map[string]interface{}{"Data": "test attestation"},
	})
	require.NoError(t, err)

	envelope, err := sigdsse.WrapSigner(sv, types.IntotoPayloadType).SignMessage(bytes.NewReader(stmt))
	require.NoError(t, err)

	att, err := static.NewAttestation(envelope)
	require.NoError(t, err)

	img, err := remote.Image(digestRef, rOpts...)
	require.NoError(t, err)
	var se oci.SignedEntity = signed.Image(img)
	se, err = mutate.AttachAttestationToEntity(se, att)
	require.NoError(t, err)

	return se
}

func pushRandomImage(t *testing.T, ref name.Reference, rOpts []remote.Option) name.Digest {
	t.Helper()
	img, err := random.Image(300, 2)
	require.NoError(t, err)
	require.NoError(t, remote.Write(ref, img, rOpts...))
	desc, err := remote.Head(ref, rOpts...)
	require.NoError(t, err)
	return ref.Context().Digest(desc.Digest.String())
}

func setupOCI11Attestation(t *testing.T) (name.Digest, oci.SignedEntity, *CheckOpts) {
	t.Helper()
	r := registry.New(registry.WithReferrersSupport(true))
	s := httptest.NewServer(r)
	t.Cleanup(s.Close)

	u, err := url.Parse(s.URL)
	require.NoError(t, err)

	// Keep all registry traffic on the httptest server and never touch the
	// ambient docker keychain/credential helpers.
	rOpts := []remote.Option{
		remote.WithTransport(s.Client().Transport),
		remote.WithAuth(authn.Anonymous),
	}
	registryClientOpts := []ociremote.Option{ociremote.WithRemoteOptions(rOpts...)}

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	sv, err := signature.LoadECDSASignerVerifier(privKey, crypto.SHA256)
	require.NoError(t, err)

	signedRef, err := name.ParseReference(fmt.Sprintf("%s/repo:signed", u.Host))
	require.NoError(t, err)
	signedDigest := pushRandomImage(t, signedRef, rOpts)
	se := newDSSEAttestationEntity(t, signedDigest, sv, rOpts)

	co := &CheckOpts{
		SigVerifier:        sv,
		IgnoreTlog:         true,
		IgnoreSCT:          true,
		ExperimentalOCI11:  true,
		RegistryClientOpts: registryClientOpts,
		ClaimVerifier:      IntotoSubjectClaimVerifier,
	}
	return signedDigest, se, co
}

func TestVerifyImageAttestationsExperimentalOCI(t *testing.T) {
	ctx := context.Background()
	for _, useTag := range []bool{false, true} {
		t.Run(fmt.Sprintf("discovers_referrer_tag=%t", useTag), func(t *testing.T) {
			ref, se, co := setupOCI11Attestation(t)
			require.NoError(t, ociremote.WriteAttestationsReferrer(ref, se, co.RegistryClientOpts...))
			var input name.Reference = ref
			if useTag {
				input = ref.Context().Tag("signed")
			}
			atts, bundleVerified, err := VerifyImageAttestations(ctx, input, co)
			require.NoError(t, err)
			assert.False(t, bundleVerified)
			require.Len(t, atts, 1)
			h, err := v1.NewHash(ref.DigestStr())
			require.NoError(t, err)
			require.NoError(t, IntotoSubjectClaimVerifier(atts[0], h, nil))
		})
	}

	t.Run("fails when the signing key does not match", func(t *testing.T) {
		ref, se, co := setupOCI11Attestation(t)
		require.NoError(t, ociremote.WriteAttestationsReferrer(ref, se, co.RegistryClientOpts...))
		otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		otherSV, err := signature.LoadECDSASignerVerifier(otherKey, crypto.SHA256)
		require.NoError(t, err)

		co.SigVerifier = otherSV
		atts, bundleVerified, err := VerifyImageAttestations(ctx, ref, co)
		require.ErrorContains(t, err, "verifying attestation referrer")
		assert.ErrorContains(t, err, "no matching attestations")
		var noMatch *ErrNoMatchingAttestations
		assert.ErrorAs(t, err, &noMatch)
		assert.Empty(t, atts)
		assert.False(t, bundleVerified)
	})

	t.Run("fails when no attestation is present", func(t *testing.T) {
		ref, _, co := setupOCI11Attestation(t)
		atts, bundleVerified, err := VerifyImageAttestations(ctx, ref, co)
		require.ErrorContains(t, err, "unable to locate any referrers")
		assert.ErrorContains(t, err, "no matching attestations")
		assert.Empty(t, atts)
		assert.False(t, bundleVerified)
	})

	t.Run("disabled by default", func(t *testing.T) {
		ref, se, co := setupOCI11Attestation(t)
		require.NoError(t, ociremote.WriteAttestationsReferrer(ref, se, co.RegistryClientOpts...))
		co.ExperimentalOCI11 = false
		_, _, err := VerifyImageAttestations(ctx, ref, co)
		assert.Error(t, err)
	})

	t.Run("falls back to legacy attestations", func(t *testing.T) {
		ref, se, co := setupOCI11Attestation(t)
		require.NoError(t, ociremote.WriteAttestations(ref.Repository, se, co.RegistryClientOpts...))
		for _, experimental := range []bool{false, true} {
			co.ExperimentalOCI11 = experimental
			atts, bundleVerified, err := VerifyImageAttestations(ctx, ref, co)
			require.NoError(t, err)
			assert.Len(t, atts, 1)
			assert.False(t, bundleVerified)
		}
	})

	t.Run("falls back after an invalid referrer", func(t *testing.T) {
		ref, se, co := setupOCI11Attestation(t)
		bad, err := static.NewAttestation([]byte("invalid envelope"))
		require.NoError(t, err)
		require.NoError(t, ociremote.WriteReferrer(ref, types.IntotoPayloadType, []v1.Layer{bad}, nil, co.RegistryClientOpts...))
		require.NoError(t, ociremote.WriteAttestations(ref.Repository, se, co.RegistryClientOpts...))
		atts, _, err := VerifyImageAttestations(ctx, ref, co)
		require.NoError(t, err)
		assert.Len(t, atts, 1)
	})

	t.Run("ignores unrelated and invalid referrers", func(t *testing.T) {
		ref, se, co := setupOCI11Attestation(t)
		bad, err := static.NewAttestation([]byte("invalid envelope"))
		require.NoError(t, err)
		require.NoError(t, ociremote.WriteReferrer(ref, "application/example", []v1.Layer{bad}, nil, co.RegistryClientOpts...))
		require.NoError(t, ociremote.WriteReferrer(ref, types.IntotoPayloadType, []v1.Layer{bad}, nil, co.RegistryClientOpts...))
		require.NoError(t, ociremote.WriteAttestationsReferrer(ref, se, co.RegistryClientOpts...))
		atts, _, err := VerifyImageAttestations(ctx, ref, co)
		require.NoError(t, err)
		assert.Len(t, atts, 1)
	})

	t.Run("verifies all matching referrers", func(t *testing.T) {
		ref, se, co := setupOCI11Attestation(t)
		require.NoError(t, ociremote.WriteAttestationsReferrer(ref, se, co.RegistryClientOpts...))
		signatures, err := se.Attestations()
		require.NoError(t, err)
		layers, err := signatures.Get()
		require.NoError(t, err)
		require.Len(t, layers, 1)
		require.NoError(t, ociremote.WriteReferrer(ref, types.IntotoPayloadType, []v1.Layer{layers[0]},
			map[string]string{"test": "second-referrer"}, co.RegistryClientOpts...))
		atts, _, err := VerifyImageAttestations(ctx, ref, co)
		require.NoError(t, err)
		assert.Len(t, atts, 2)
	})

	t.Run("uses the target repository", func(t *testing.T) {
		ref, se, co := setupOCI11Attestation(t)
		target, err := name.NewRepository(ref.RegistryStr() + "/attestations")
		require.NoError(t, err)
		opts := append([]ociremote.Option{}, co.RegistryClientOpts...)
		opts = append(opts, ociremote.WithTargetRepository(target))
		require.NoError(t, ociremote.WriteAttestationsReferrer(ref, se, opts...))
		_, _, err = VerifyImageAttestations(ctx, ref, co)
		require.Error(t, err)
		co.RegistryClientOpts = opts
		atts, _, err := VerifyImageAttestations(ctx, ref, co)
		require.NoError(t, err)
		assert.Len(t, atts, 1)
	})

	t.Run("checks the subject digest", func(t *testing.T) {
		ref, se, co := setupOCI11Attestation(t)
		rOpts := []remote.Option{remote.WithAuth(authn.Anonymous)}
		otherRef := pushRandomImage(t, ref.Context().Tag("other"), rOpts)
		require.NoError(t, ociremote.WriteAttestationsReferrer(otherRef, se, co.RegistryClientOpts...))
		_, _, err := VerifyImageAttestations(ctx, otherRef, co)
		assert.ErrorContains(t, err, "verifying attestation referrer")
	})

	t.Run("requires verification material", func(t *testing.T) {
		ref, _, co := setupOCI11Attestation(t)
		co.SigVerifier = nil
		_, _, err := VerifyImageAttestations(ctx, ref, co)
		require.EqualError(t, err, "one of verifier, root certs, or TrustedMaterial is required")
	})

	t.Run("falls back when referrer discovery fails", func(t *testing.T) {
		ref, se, co := setupOCI11Attestation(t)
		require.NoError(t, ociremote.WriteAttestations(ref.Repository, se, co.RegistryClientOpts...))
		co.RegistryClientOpts = []ociremote.Option{ociremote.WithRemoteOptions(
			remote.WithAuth(authn.Anonymous),
			remote.WithTransport(attestationRoundTripper(func(req *http.Request) (*http.Response, error) {
				if strings.Contains(req.URL.Path, "/referrers/") {
					return &http.Response{
						StatusCode: http.StatusForbidden,
						Header:     make(http.Header),
						Body:       io.NopCloser(strings.NewReader("referrers access denied")),
						Request:    req,
					}, nil
				}
				return remote.DefaultTransport.RoundTrip(req)
			})),
		)}
		atts, _, err := VerifyImageAttestations(ctx, ref, co)
		require.NoError(t, err)
		assert.Len(t, atts, 1)
	})

	t.Run("preserves referrer fetch errors", func(t *testing.T) {
		ref, se, co := setupOCI11Attestation(t)
		require.NoError(t, ociremote.WriteAttestationsReferrer(ref, se, co.RegistryClientOpts...))
		co.RegistryClientOpts = []ociremote.Option{ociremote.WithRemoteOptions(
			remote.WithAuth(authn.Anonymous),
			remote.WithTransport(attestationRoundTripper(func(req *http.Request) (*http.Response, error) {
				if strings.Contains(req.URL.Path, "/manifests/") {
					return &http.Response{
						StatusCode: http.StatusForbidden,
						Header:     make(http.Header),
						Body:       io.NopCloser(strings.NewReader("attestation access denied")),
						Request:    req,
					}, nil
				}
				return remote.DefaultTransport.RoundTrip(req)
			})),
		)}
		_, _, err := VerifyImageAttestations(ctx, ref, co)
		require.ErrorContains(t, err, "fetching attestation referrer")
		assert.ErrorContains(t, err, "attestation access denied")
		var transportErr *transport.Error
		require.ErrorAs(t, err, &transportErr)
		assert.Equal(t, http.StatusForbidden, transportErr.StatusCode)
	})

	t.Run("bundle format does not accept a DSSE-only referrer", func(t *testing.T) {
		ref, se, co := setupOCI11Attestation(t)
		require.NoError(t, ociremote.WriteAttestationsReferrer(ref, se, co.RegistryClientOpts...))
		co.NewBundleFormat = true
		atts, bundleVerified, err := VerifyImageAttestations(ctx, ref, co)
		var noMatch *ErrNoMatchingAttestations
		require.ErrorAs(t, err, &noMatch)
		assert.Empty(t, atts)
		assert.False(t, bundleVerified)
	})
}

type attestationRoundTripper func(*http.Request) (*http.Response, error)

func (f attestationRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
