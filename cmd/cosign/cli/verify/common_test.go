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
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/cosign/env"
)

func TestSetTrustedMaterialNewBundleTUFError(t *testing.T) {
	setBrokenTrustedRootTUFEnv(t)

	co := &cosign.CheckOpts{}
	err := SetTrustedMaterial("", false, co)

	if err == nil {
		t.Fatal("expected trusted root TUF error")
	}
	if !strings.Contains(err.Error(), "getting trusted root from TUF for bundle verification") {
		t.Fatalf("expected bundle trusted root error, got %v", err)
	}
	if !strings.Contains(err.Error(), "error reading root.json given by TUF_ROOT_JSON") {
		t.Fatalf("expected underlying TUF error, got %v", err)
	}
	if co.TrustedMaterial != nil {
		t.Fatal("expected TrustedMaterial to remain unset")
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
