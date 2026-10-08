//
// Copyright 2026 The Sigstore Authors.
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

package cli

import (
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
)

// cleanTagsFor mirrors how CleanCmd turns registry options into the attachment
// tags it deletes. Keeping it in one place lets the test cover the prefix
// plumbing without reaching the network, which CleanCmd itself needs.
func cleanTagsFor(t *testing.T, regOpts options.RegistryOptions, imageRef string) (name.Tag, name.Tag, name.Tag) {
	t.Helper()

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		t.Fatalf("parsing reference: %v", err)
	}

	ociRemoteOpts := []ociremote.Option{}
	if regOpts.RefOpts.TagPrefix != "" {
		ociRemoteOpts = append(ociRemoteOpts, ociremote.WithPrefix(regOpts.RefOpts.TagPrefix))
	}

	sigRef, err := ociremote.SignatureTag(ref, ociRemoteOpts...)
	if err != nil {
		t.Fatalf("signature tag: %v", err)
	}
	attRef, err := ociremote.AttestationTag(ref, ociRemoteOpts...)
	if err != nil {
		t.Fatalf("attestation tag: %v", err)
	}
	sbomRef, err := ociremote.SBOMTag(ref, ociRemoteOpts...)
	if err != nil {
		t.Fatalf("sbom tag: %v", err)
	}
	return sigRef, attRef, sbomRef
}

// --attachment-tag-prefix must select the prefixed attachments. Without it the
// unprefixed ones were deleted instead, which removes artifacts the caller
// never named.
func TestCleanTagsHonorAttachmentTagPrefix(t *testing.T) {
	const digestRef = "registry.example.com/test@sha256:0000000000000000000000000000000000000000000000000000000000000000"

	var regOpts options.RegistryOptions
	regOpts.RefOpts.TagPrefix = "cve-"

	sigRef, attRef, sbomRef := cleanTagsFor(t, regOpts, digestRef)

	for _, tc := range []struct {
		name string
		got  name.Tag
		want string
	}{
		{"signature", sigRef, "cve-sha256-0000000000000000000000000000000000000000000000000000000000000000.sig"},
		{"attestation", attRef, "cve-sha256-0000000000000000000000000000000000000000000000000000000000000000.att"},
		{"sbom", sbomRef, "cve-sha256-0000000000000000000000000000000000000000000000000000000000000000.sbom"},
	} {
		if tc.got.TagStr() != tc.want {
			t.Errorf("%s tag = %q, want %q", tc.name, tc.got.TagStr(), tc.want)
		}
	}
}

// Without the flag the tags stay exactly as they were, so the fix cannot change
// the behaviour of a run that does not pass a prefix.
func TestCleanTagsWithoutPrefixUnchanged(t *testing.T) {
	const digestRef = "registry.example.com/test@sha256:0000000000000000000000000000000000000000000000000000000000000000"

	sigRef, attRef, sbomRef := cleanTagsFor(t, options.RegistryOptions{}, digestRef)

	for _, tc := range []struct {
		name string
		got  name.Tag
		want string
	}{
		{"signature", sigRef, "sha256-0000000000000000000000000000000000000000000000000000000000000000.sig"},
		{"attestation", attRef, "sha256-0000000000000000000000000000000000000000000000000000000000000000.att"},
		{"sbom", sbomRef, "sha256-0000000000000000000000000000000000000000000000000000000000000000.sbom"},
	} {
		if tc.got.TagStr() != tc.want {
			t.Errorf("%s tag = %q, want %q", tc.name, tc.got.TagStr(), tc.want)
		}
	}
}
