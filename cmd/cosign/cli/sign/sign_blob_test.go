// Copyright 2024 The Sigstore Authors.
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

package sign

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/pkg/cosign"
)

func TestSignBlobCmd(t *testing.T) {
	td := t.TempDir()
	bundlePath := filepath.Join(td, "bundle.sigstore.json")

	keys, _ := cosign.GenerateKeyPair(nil)
	keyRef := writeFile(t, td, string(keys.PrivateBytes), "key.pem")

	blob := []byte("foo")
	blobPath := writeFile(t, td, string(blob), "foo.txt")

	rootOpts := &options.RootOptions{}
	keyOpts := options.KeyOpts{KeyRef: keyRef, BundlePath: bundlePath}

	// Test happy path
	_, err := SignBlobCmd(rootOpts, keyOpts, blobPath, true, "", "", false)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}

	// Test file outputs
	keyOpts.NewBundleFormat = true
	sigPath := filepath.Join(td, "output.sig")
	certPath := filepath.Join(td, "output.pem")
	_, err = SignBlobCmd(rootOpts, keyOpts, blobPath, false, sigPath, certPath, false)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
}

func writeFile(t *testing.T, td string, blob string, name string) string {
	// Write blob to disk
	blobPath := filepath.Join(td, name)
	if err := os.WriteFile(blobPath, []byte(blob), 0644); err != nil {
		t.Fatal(err)
	}
	return blobPath
}

func TestSignBlobCmd_LegacyBundleNoCert(t *testing.T) {
	td := t.TempDir()
	bundlePath := filepath.Join(td, "legacy-bundle.json")

	keys, _ := cosign.GenerateKeyPair(nil)
	keyRef := writeFile(t, td, string(keys.PrivateBytes), "key.pem")

	blob := []byte("foo")
	blobPath := writeFile(t, td, string(blob), "foo.txt")

	rootOpts := &options.RootOptions{}
	keyOpts := options.KeyOpts{
		KeyRef:          keyRef,
		BundlePath:      bundlePath,
		NewBundleFormat: false,
	}

	_, err := SignBlobCmd(rootOpts, keyOpts, blobPath, true, "", "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	bundleBytes, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("failed to read written bundle file: %v", err)
	}

	var payload cosign.LocalSignedPayload
	if err := json.Unmarshal(bundleBytes, &payload); err != nil {
		t.Fatalf("failed to unmarshal legacy bundle: %v", err)
	}

	if payload.Cert != "" {
		t.Fatalf("expected empty cert field in legacy bundle when signing with a key without certificate, got: %q", payload.Cert)
	}
	if payload.Base64Signature == "" {
		t.Fatal("expected non-empty Base64Signature in legacy bundle")
	}
}
