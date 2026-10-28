// Copyright 2026 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package verify

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigstore/cosign/v3/internal/ui"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/cosign/env"
)

func TestSetTrustedMaterialNewBundleTUFError(t *testing.T) {
	setBrokenTrustedRootTUFEnv(t)

	co := &cosign.CheckOpts{NewBundleFormat: true}
	var err error
	stderr := ui.RunWithTestCtx(func(ctx context.Context, _ ui.WriteFunc) {
		err = SetTrustedMaterial(ctx, "", "", "", "", "", false, co)
	})

	if err == nil {
		t.Fatal("expected trusted root TUF error")
	}
	if !strings.Contains(err.Error(), "getting trusted root from TUF for new bundle verification") {
		t.Fatalf("expected new bundle trusted root error, got %v", err)
	}
	if !strings.Contains(err.Error(), "error reading root.json given by TUF_ROOT_JSON") {
		t.Fatalf("expected underlying TUF error, got %v", err)
	}
	if co.TrustedMaterial != nil {
		t.Fatal("expected TrustedMaterial to remain unset")
	}
	if stderr != "" {
		t.Fatalf("expected no warning when returning new bundle error, got %q", stderr)
	}
}

func TestSetTrustedMaterialLegacyTUFFallback(t *testing.T) {
	setBrokenTrustedRootTUFEnv(t)

	co := &cosign.CheckOpts{}
	var err error
	stderr := ui.RunWithTestCtx(func(ctx context.Context, _ ui.WriteFunc) {
		err = SetTrustedMaterial(ctx, "", "", "", "", "", false, co)
	})

	if err != nil {
		t.Fatalf("expected legacy trusted material fallback, got %v", err)
	}
	if co.TrustedMaterial != nil {
		t.Fatal("expected TrustedMaterial to remain unset")
	}
	if !strings.Contains(stderr, "Could not fetch trusted_root.json from the TUF repository") {
		t.Fatalf("expected legacy fallback warning, got %q", stderr)
	}
}

func TestPrintVerificationHeaderIncludesCertificateAndTimestampChecks(t *testing.T) {
	co := &cosign.CheckOpts{
		ClaimVerifier:       cosign.SimpleClaimVerifier,
		UseSignedTimestamps: true,
	}

	stderr := ui.RunWithTestCtx(func(ctx context.Context, _ ui.WriteFunc) {
		PrintVerificationHeader(ctx, "example.com/repo/image:tag", co, false, false, true)
	})

	for _, want := range []string{
		"Verification for example.com/repo/image:tag --",
		"The following checks were performed on each of these signatures:",
		"  - The cosign claims were validated",
		"  - The signing certificate was verified using trusted certificate authority certificates",
		"  - The RFC3161 timestamp was verified using trusted timestamp authority certificates",
	} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("expected header to contain %q, got %q", want, stderr)
		}
	}
}

func setBrokenTrustedRootTUFEnv(t *testing.T) {
	t.Helper()
	t.Setenv(env.VariableTUFRootDir.String(), t.TempDir())
	t.Setenv(env.VariableTUFMirror.String(), "https://example.com/tuf")
	t.Setenv(env.VariableTUFRootJSON.String(), filepath.Join(t.TempDir(), "missing-root.json"))
	t.Setenv(env.VariableSigstoreCTLogPublicKeyFile.String(), "")
	t.Setenv(env.VariableSigstoreRootFile.String(), "")
	t.Setenv(env.VariableSigstoreRekorPublicKey.String(), "")
	t.Setenv(env.VariableSigstoreTSACertificateFile.String(), "")
}
