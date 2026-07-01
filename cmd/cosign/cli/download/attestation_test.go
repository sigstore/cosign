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

package download

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
)

// stubSeams replaces the two registry-touching stages of AttestationCmd for the
// duration of a test and restores the originals afterward, so the command flow
// can be exercised without contacting a registry.
func stubSeams(t *testing.T,
	wnb func(context.Context, name.Reference, []ociremote.Option, string, io.Writer) (int, error),
	woa func(name.Reference, []ociremote.Option, string, string, io.Writer) error,
) {
	t.Helper()
	origWNB := writeNewBundles
	origWOA := writeOldAttestations
	writeNewBundles = wnb
	writeOldAttestations = woa
	t.Cleanup(func() {
		writeNewBundles = origWNB
		writeOldAttestations = origWOA
	})
}

const testDigestRef = "ghcr.io/example/image@sha256:0000000000000000000000000000000000000000000000000000000000000000"

// TestAttestationDownloadEmitsBothFormats covers issue #4573: an image that
// carries a new-format sigstore bundle referrer (for example a signature-only
// bundle) must not cause the old-format sha256-<digest>.att attestations to be
// skipped. download is an inspection command and should emit both formats.
func TestAttestationDownloadEmitsBothFormats(t *testing.T) {
	stubSeams(t,
		func(_ context.Context, _ name.Reference, _ []ociremote.Option, _ string, out io.Writer) (int, error) {
			_, err := out.Write([]byte("new-bundle-line\n"))
			return 1, err
		},
		func(_ name.Reference, _ []ociremote.Option, _, _ string, out io.Writer) error {
			_, err := out.Write([]byte("old-format-att-line\n"))
			return err
		},
	)

	var buf bytes.Buffer
	if err := AttestationCmd(context.Background(), options.RegistryOptions{}, options.AttestationDownloadOptions{}, testDigestRef, &buf); err != nil {
		t.Fatalf("AttestationCmd returned error: %v", err)
	}

	got := buf.String()
	if !strings.Contains(got, "new-bundle-line") {
		t.Errorf("expected new-format bundle in output, got:\n%s", got)
	}
	// Regression assertion for #4573: on the unpatched code the command returned
	// right after the new-format branch, so the old-format .att attestation was
	// never fetched or written.
	if !strings.Contains(got, "old-format-att-line") {
		t.Errorf("old-format attestation was dropped when a new-format bundle was present (issue #4573); output:\n%s", got)
	}
}

// TestAttestationDownloadNewFormatOnlyToleratesMissingOldFormat verifies that
// once a new-format bundle is written, a missing old-format entity (or an image
// with no old-format attestations) is not fatal.
func TestAttestationDownloadNewFormatOnlyToleratesMissingOldFormat(t *testing.T) {
	stubSeams(t,
		func(_ context.Context, _ name.Reference, _ []ociremote.Option, _ string, out io.Writer) (int, error) {
			_, err := out.Write([]byte("new-bundle-line\n"))
			return 1, err
		},
		func(_ name.Reference, _ []ociremote.Option, _, _ string, _ io.Writer) error {
			return errors.New("found no attestations")
		},
	)

	var buf bytes.Buffer
	if err := AttestationCmd(context.Background(), options.RegistryOptions{}, options.AttestationDownloadOptions{}, testDigestRef, &buf); err != nil {
		t.Fatalf("expected no error when a new-format bundle was written and no old-format attestations exist, got: %v", err)
	}
	if !strings.Contains(buf.String(), "new-bundle-line") {
		t.Errorf("expected new-format bundle in output, got:\n%s", buf.String())
	}
}

// TestAttestationDownloadNoNewFormatStillSurfacesError makes sure the fix does
// not change behavior for an image with no new-format bundles: an old-format
// lookup that finds nothing must still surface the error.
func TestAttestationDownloadNoNewFormatStillSurfacesError(t *testing.T) {
	stubSeams(t,
		func(_ context.Context, _ name.Reference, _ []ociremote.Option, _ string, _ io.Writer) (int, error) {
			return 0, nil // no new-format bundles
		},
		func(_ name.Reference, _ []ociremote.Option, _, _ string, _ io.Writer) error {
			return errors.New("found no attestations")
		},
	)

	var buf bytes.Buffer
	err := AttestationCmd(context.Background(), options.RegistryOptions{}, options.AttestationDownloadOptions{}, testDigestRef, &buf)
	if err == nil {
		t.Fatalf("expected an error when no attestations of either format exist, got nil (output: %q)", buf.String())
	}
}
