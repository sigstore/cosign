//
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

package remote

import (
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

const testDigestStr = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func TestReferrers_NoTargetRepository(t *testing.T) {
	orig := remoteReferrers
	t.Cleanup(func() { remoteReferrers = orig })

	var capturedDigest name.Digest
	remoteReferrers = func(d name.Digest, _ ...remote.Option) (v1.ImageIndex, error) {
		capturedDigest = d
		return empty.Index, nil
	}

	inputDigest, err := name.NewDigest("gcr.io/source-repo/image@" + testDigestStr)
	if err != nil {
		t.Fatalf("name.NewDigest: %v", err)
	}

	if _, err = Referrers(inputDigest, ""); err != nil {
		t.Fatalf("Referrers() = %v", err)
	}

	if got, want := capturedDigest.Repository.String(), inputDigest.Repository.String(); got != want {
		t.Errorf("repository = %q, want %q", got, want)
	}
	if got, want := capturedDigest.DigestStr(), testDigestStr; got != want {
		t.Errorf("digest = %q, want %q", got, want)
	}
}

func TestReferrers_WithTargetRepository(t *testing.T) {
	orig := remoteReferrers
	t.Cleanup(func() { remoteReferrers = orig })

	var capturedDigest name.Digest
	remoteReferrers = func(d name.Digest, _ ...remote.Option) (v1.ImageIndex, error) {
		capturedDigest = d
		return empty.Index, nil
	}

	inputDigest, err := name.NewDigest("gcr.io/source-repo/image@" + testDigestStr)
	if err != nil {
		t.Fatalf("name.NewDigest: %v", err)
	}
	targetRepo, err := name.NewRepository("gcr.io/target-repo/other")
	if err != nil {
		t.Fatalf("name.NewRepository: %v", err)
	}

	if _, err = Referrers(inputDigest, "", WithTargetRepository(targetRepo)); err != nil {
		t.Fatalf("Referrers() = %v", err)
	}

	// The digest must be redirected to the target repository.
	if got, want := capturedDigest.Repository.String(), targetRepo.String(); got != want {
		t.Errorf("repository = %q, want %q", got, want)
	}
	// The digest hash itself must be preserved.
	if got, want := capturedDigest.DigestStr(), testDigestStr; got != want {
		t.Errorf("digest = %q, want %q", got, want)
	}
}

func TestReferrers_ArtifactTypeFilter(t *testing.T) {
	orig := remoteReferrers
	t.Cleanup(func() { remoteReferrers = orig })

	inputDigest, err := name.NewDigest("gcr.io/source-repo/image@" + testDigestStr)
	if err != nil {
		t.Fatalf("name.NewDigest: %v", err)
	}

	// Capture baseline option count (no artifact type filter).
	var baselineOptCount int
	remoteReferrers = func(_ name.Digest, opts ...remote.Option) (v1.ImageIndex, error) {
		baselineOptCount = len(opts)
		return empty.Index, nil
	}
	if _, err = Referrers(inputDigest, ""); err != nil {
		t.Fatalf("Referrers() baseline = %v", err)
	}

	// Now with an artifact type filter — should add one extra option.
	var capturedOptCount int
	remoteReferrers = func(_ name.Digest, opts ...remote.Option) (v1.ImageIndex, error) {
		capturedOptCount = len(opts)
		return empty.Index, nil
	}
	if _, err = Referrers(inputDigest, "application/vnd.example.type"); err != nil {
		t.Fatalf("Referrers() with filter = %v", err)
	}

	if capturedOptCount != baselineOptCount+1 {
		t.Errorf("expected %d options (baseline %d + 1 filter), got %d", baselineOptCount+1, baselineOptCount, capturedOptCount)
	}
}
