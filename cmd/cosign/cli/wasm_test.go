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
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/wasm"
)

func TestStripWasmSignatures(t *testing.T) {
	td := t.TempDir()
	module := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}

	var err error
	module, err = wasm.AppendSignatureSection(module, []byte("first-bundle"))
	if err != nil {
		t.Fatal(err)
	}
	module, err = wasm.AppendSignatureSection(module, []byte("second-bundle"))
	if err != nil {
		t.Fatal(err)
	}

	inputPath := filepath.Join(td, "signed.wasm")
	if err := os.WriteFile(inputPath, module, 0644); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(td, "unsigned.wasm")

	if err := stripWasmSignatures(inputPath, outputPath); err != nil {
		t.Fatal(err)
	}

	stripped, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
	if !bytes.Equal(stripped, want) {
		t.Fatalf("stripped module = %x, want %x", stripped, want)
	}
}

func TestListWasmSignatures(t *testing.T) {
	td := t.TempDir()
	module := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}

	var err error
	module, err = wasm.AppendSignatureSection(module, []byte("first-bundle"))
	if err != nil {
		t.Fatal(err)
	}
	module, err = wasm.AppendSignatureSection(module, []byte("second-bundle"))
	if err != nil {
		t.Fatal(err)
	}

	inputPath := filepath.Join(td, "signed.wasm")
	if err := os.WriteFile(inputPath, module, 0o644); err != nil {
		t.Fatal(err)
	}

	output := captureStdout(t, func() error {
		return listWasmSignatures(inputPath, "text")
	})

	firstDigest := sha256.Sum256([]byte("first-bundle"))
	secondDigest := sha256.Sum256([]byte("second-bundle"))
	if !strings.Contains(output, "INDEX") || !strings.Contains(output, hex.EncodeToString(firstDigest[:])) || !strings.Contains(output, hex.EncodeToString(secondDigest[:])) {
		t.Fatalf("text output = %q, want header and both signature digests", output)
	}

	output = captureStdout(t, func() error {
		return listWasmSignatures(inputPath, "json")
	})
	if !strings.Contains(output, `"index": 0`) || !strings.Contains(output, `"payloadSize": 12`) || !strings.Contains(output, hex.EncodeToString(secondDigest[:])) {
		t.Fatalf("json output = %q, want signature metadata", output)
	}
}

func TestSignWasmBlobAppendsSignatureSection(t *testing.T) {
	oldTimeout := ro.Timeout
	ro.Timeout = time.Minute
	defer func() { ro.Timeout = oldTimeout }()

	td := t.TempDir()

	keys, _ := cosign.GenerateKeyPair(nil)
	keyPath := filepath.Join(td, "key.pem")
	if err := os.WriteFile(keyPath, keys.PrivateBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	module := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
	module, err := wasm.AppendSignatureSection(module, []byte("first-bundle"))
	if err != nil {
		t.Fatal(err)
	}

	inputPath := filepath.Join(td, "input.wasm")
	if err := os.WriteFile(inputPath, module, 0o644); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(td, "signed.wasm")

	ko := options.KeyOpts{
		KeyRef:          keyPath,
		NewBundleFormat: true,
	}

	if err := signWasmBlob(t.Context(), ko, inputPath, "", "", false, "", "", false, outputPath); err != nil {
		t.Fatal(err)
	}

	signed, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}

	stripped, sections, err := wasm.StripAndExtractSignatureSections(signed)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(sections), 2; got != want {
		t.Fatalf("len(sections) = %d, want %d", got, want)
	}
	if !bytes.Equal(sections[0], []byte("first-bundle")) {
		t.Fatalf("sections[0] = %q, want first-bundle", sections[0])
	}
	if len(sections[1]) == 0 {
		t.Fatal("sections[1] is empty")
	}
	want := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
	if !bytes.Equal(stripped, want) {
		t.Fatalf("stripped module = %x, want %x", stripped, want)
	}
}

func captureStdout(t *testing.T, fn func() error) string {
	t.Helper()

	originalStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	err = fn()
	_ = w.Close()
	os.Stdout = originalStdout
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}
