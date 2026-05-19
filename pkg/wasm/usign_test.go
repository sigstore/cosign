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

package wasm

import (
	"bytes"
	"testing"
)

func TestStripAndExtractSignatureSections(t *testing.T) {
	module := minimalModule(t)
	module = mustAppendCustomSection(t, module, "producers", []byte("toolchain"))
	module = mustAppendCustomSection(t, module, SignatureSectionName, []byte("first-bundle"))
	module = append(module, 1, 1, 0) // type section with an empty vector.
	module = mustAppendCustomSection(t, module, SignatureSectionName, []byte("second-bundle"))

	stripped, sections, err := StripAndExtractSignatureSections(module)
	if err != nil {
		t.Fatalf("StripAndExtractSignatureSections() error = %v", err)
	}

	if got, want := len(sections), 2; got != want {
		t.Fatalf("len(sections) = %d, want %d", got, want)
	}
	if !bytes.Equal(sections[0], []byte("first-bundle")) {
		t.Fatalf("sections[0] = %q, want first-bundle", sections[0])
	}
	if !bytes.Equal(sections[1], []byte("second-bundle")) {
		t.Fatalf("sections[1] = %q, want second-bundle", sections[1])
	}
	if bytes.Contains(stripped, []byte(SignatureSectionName)) {
		t.Fatalf("stripped module still contains %q", SignatureSectionName)
	}
	if !bytes.Contains(stripped, []byte("producers")) {
		t.Fatalf("stripped module removed a non-signature custom section")
	}
}

func TestAppendSignatureSectionPreservesExistingSections(t *testing.T) {
	module := minimalModule(t)
	module = mustAppendCustomSection(t, module, SignatureSectionName, []byte("old-bundle"))

	signed, err := AppendSignatureSection(module, []byte("new-bundle"))
	if err != nil {
		t.Fatalf("AppendSignatureSection() error = %v", err)
	}

	stripped, sections, err := StripAndExtractSignatureSections(signed)
	if err != nil {
		t.Fatalf("StripAndExtractSignatureSections() error = %v", err)
	}
	if got, want := len(sections), 2; got != want {
		t.Fatalf("len(sections) = %d, want %d", got, want)
	}
	if !bytes.Equal(sections[0], []byte("old-bundle")) {
		t.Fatalf("sections[0] = %q, want old-bundle", sections[0])
	}
	if !bytes.Equal(sections[1], []byte("new-bundle")) {
		t.Fatalf("sections[1] = %q, want new-bundle", sections[1])
	}
	if !bytes.Equal(stripped, minimalModule(t)) {
		t.Fatalf("stripped signed module = %x, want minimal module", stripped)
	}
}

func TestInspectSignatureSections(t *testing.T) {
	module := minimalModule(t)
	module = mustAppendCustomSection(t, module, "producers", []byte("toolchain"))
	firstOffset := len(module)
	module = mustAppendCustomSection(t, module, SignatureSectionName, []byte("first-bundle"))
	module = append(module, 1, 1, 0) // type section with an empty vector.
	secondOffset := len(module)
	module = mustAppendCustomSection(t, module, SignatureSectionName, []byte("second-bundle"))

	sections, err := InspectSignatureSections(module)
	if err != nil {
		t.Fatalf("InspectSignatureSections() error = %v", err)
	}
	if got, want := len(sections), 2; got != want {
		t.Fatalf("len(sections) = %d, want %d", got, want)
	}
	if sections[0].Index != 0 || sections[0].Offset != firstOffset || sections[0].PayloadSize != len("first-bundle") {
		t.Fatalf("sections[0] = %+v, want index 0 offset %d payload size %d", sections[0], firstOffset, len("first-bundle"))
	}
	if sections[1].Index != 1 || sections[1].Offset != secondOffset || sections[1].PayloadSize != len("second-bundle") {
		t.Fatalf("sections[1] = %+v, want index 1 offset %d payload size %d", sections[1], secondOffset, len("second-bundle"))
	}
	if !bytes.Equal(sections[0].Payload, []byte("first-bundle")) {
		t.Fatalf("sections[0].Payload = %q, want first-bundle", sections[0].Payload)
	}
	if !bytes.Equal(sections[1].Payload, []byte("second-bundle")) {
		t.Fatalf("sections[1].Payload = %q, want second-bundle", sections[1].Payload)
	}
}

func TestReplaceSignatureSectionReplacesExistingSections(t *testing.T) {
	module := minimalModule(t)
	module = mustAppendCustomSection(t, module, SignatureSectionName, []byte("old-bundle"))

	signed, err := ReplaceSignatureSection(module, []byte("new-bundle"))
	if err != nil {
		t.Fatalf("ReplaceSignatureSection() error = %v", err)
	}

	stripped, sections, err := StripAndExtractSignatureSections(signed)
	if err != nil {
		t.Fatalf("StripAndExtractSignatureSections() error = %v", err)
	}
	if got, want := len(sections), 1; got != want {
		t.Fatalf("len(sections) = %d, want %d", got, want)
	}
	if !bytes.Equal(sections[0], []byte("new-bundle")) {
		t.Fatalf("sections[0] = %q, want new-bundle", sections[0])
	}
	if !bytes.Equal(stripped, minimalModule(t)) {
		t.Fatalf("stripped signed module = %x, want minimal module", stripped)
	}
}

func TestStripRejectsInvalidModule(t *testing.T) {
	if _, err := StripSignatureSections([]byte("not wasm")); err == nil {
		t.Fatalf("StripSignatureSections() error = nil, want error")
	}
}

func TestAppendRejectsInvalidModule(t *testing.T) {
	if _, err := AppendSignatureSection([]byte("not wasm"), []byte("bundle")); err == nil {
		t.Fatalf("AppendSignatureSection() error = nil, want error")
	}
}

func minimalModule(t *testing.T) []byte {
	t.Helper()
	return []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
}

func mustAppendCustomSection(t *testing.T, module []byte, name string, payload []byte) []byte {
	t.Helper()
	out, err := appendCustomSection(module, name, payload)
	if err != nil {
		t.Fatalf("appendCustomSection(%q) error = %v", name, err)
	}
	return out
}
