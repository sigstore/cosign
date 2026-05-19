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
	"errors"
	"fmt"
)

const (
	// SignatureSectionName is the WebAssembly custom section name used to store
	// embedded Sigstore verification material.
	SignatureSectionName = "wasm-cosign"

	customSectionID = byte(0)
	headerLen       = 8
)

// SignatureSection describes one embedded wasm-cosign custom section.
type SignatureSection struct {
	Index       int
	Offset      int
	SectionSize uint32
	PayloadSize int
	Payload     []byte
}

var (
	wasmMagic   = []byte{0x00, 0x61, 0x73, 0x6d}
	wasmVersion = []byte{0x01, 0x00, 0x00, 0x00}
)

// StripSignatureSections returns a copy of module with every custom section
// named "wasm-cosign" removed. All other bytes are preserved exactly.
func StripSignatureSections(module []byte) ([]byte, error) {
	stripped, _, err := StripAndExtractSignatureSections(module)
	return stripped, err
}

// ExtractSignatureSections returns the payloads from every "wasm-cosign" custom
// section without modifying the module.
func ExtractSignatureSections(module []byte) ([][]byte, error) {
	_, sections, err := StripAndExtractSignatureSections(module)
	return sections, err
}

// InspectSignatureSections returns metadata for every "wasm-cosign" custom
// section without modifying the module.
func InspectSignatureSections(module []byte) ([]SignatureSection, error) {
	_, sections, err := stripInspectSignatureSections(module)
	return sections, err
}

// StripAndExtractSignatureSections returns a copy of module with embedded
// signatures removed, plus the raw payload from every removed signature section.
func StripAndExtractSignatureSections(module []byte) ([]byte, [][]byte, error) {
	stripped, sections, err := stripInspectSignatureSections(module)
	if err != nil {
		return nil, nil, err
	}

	payloads := make([][]byte, 0, len(sections))
	for _, section := range sections {
		payloads = append(payloads, section.Payload)
	}

	return stripped, payloads, nil
}

func stripInspectSignatureSections(module []byte) ([]byte, []SignatureSection, error) {
	if err := validateHeader(module); err != nil {
		return nil, nil, err
	}

	out := append([]byte(nil), module[:headerLen]...)
	var signatureSections []SignatureSection

	for pos := headerLen; pos < len(module); {
		sectionStart := pos
		sectionID := module[pos]
		pos++

		sectionSize, n, err := readVaruint32(module[pos:])
		if err != nil {
			return nil, nil, fmt.Errorf("reading section size at byte %d: %w", pos, err)
		}
		pos += n

		if uint64(sectionSize) > uint64(len(module)-pos) {
			return nil, nil, fmt.Errorf("section at byte %d extends past end of module", sectionStart)
		}
		sectionEnd := pos + int(sectionSize)
		sectionPayload := module[pos:sectionEnd]

		if sectionID == customSectionID {
			name, payload, err := splitCustomSection(sectionPayload)
			if err != nil {
				return nil, nil, fmt.Errorf("reading custom section at byte %d: %w", sectionStart, err)
			}
			if name == SignatureSectionName {
				signatureSections = append(signatureSections, SignatureSection{
					Index:       len(signatureSections),
					Offset:      sectionStart,
					SectionSize: sectionSize,
					PayloadSize: len(payload),
					Payload:     append([]byte(nil), payload...),
				})
				pos = sectionEnd
				continue
			}
		}

		out = append(out, module[sectionStart:sectionEnd]...)
		pos = sectionEnd
	}

	return out, signatureSections, nil
}

// ReplaceSignatureSection strips any existing "wasm-cosign" custom sections and
// appends a new one. WebAssembly runtimes ignore custom sections, so appending
// this section preserves module execution semantics.
func ReplaceSignatureSection(module, payload []byte) ([]byte, error) {
	stripped, err := StripSignatureSections(module)
	if err != nil {
		return nil, err
	}
	return appendCustomSection(stripped, SignatureSectionName, payload)
}

// AppendSignatureSection appends a new "wasm-cosign" custom section while
// preserving any existing embedded signatures.
func AppendSignatureSection(module, payload []byte) ([]byte, error) {
	if _, _, err := StripAndExtractSignatureSections(module); err != nil {
		return nil, err
	}
	return appendCustomSection(module, SignatureSectionName, payload)
}

func validateHeader(module []byte) error {
	if len(module) < headerLen {
		return errors.New("module is shorter than the WebAssembly header")
	}
	if !bytes.Equal(module[:4], wasmMagic) {
		return errors.New("module does not start with the WebAssembly magic header")
	}
	if !bytes.Equal(module[4:headerLen], wasmVersion) {
		return fmt.Errorf("unsupported WebAssembly version %x", module[4:headerLen])
	}
	return nil
}

func splitCustomSection(sectionPayload []byte) (string, []byte, error) {
	nameLen, n, err := readVaruint32(sectionPayload)
	if err != nil {
		return "", nil, fmt.Errorf("reading custom section name length: %w", err)
	}
	if uint64(nameLen) > uint64(len(sectionPayload)-n) {
		return "", nil, errors.New("custom section name extends past section payload")
	}

	nameStart := n
	nameEnd := nameStart + int(nameLen)
	return string(sectionPayload[nameStart:nameEnd]), sectionPayload[nameEnd:], nil
}

func appendCustomSection(module []byte, name string, payload []byte) ([]byte, error) {
	if err := validateHeader(module); err != nil {
		return nil, err
	}

	sectionPayload := make([]byte, 0, 5+len(name)+len(payload))
	sectionPayload = append(sectionPayload, encodeVaruint32(uint32(len(name)))...)
	sectionPayload = append(sectionPayload, name...)
	sectionPayload = append(sectionPayload, payload...)

	section := make([]byte, 0, 1+5+len(sectionPayload))
	section = append(section, customSectionID)
	section = append(section, encodeVaruint32(uint32(len(sectionPayload)))...)
	section = append(section, sectionPayload...)

	out := append([]byte(nil), module...)
	out = append(out, section...)
	return out, nil
}

func readVaruint32(data []byte) (uint32, int, error) {
	var value uint32
	for i := 0; i < 5; i++ {
		if i >= len(data) {
			return 0, 0, errors.New("unexpected end of data")
		}
		b := data[i]
		if i == 4 && b&0xf0 != 0 {
			return 0, 0, errors.New("varuint32 overflows 32 bits")
		}
		value |= uint32(b&0x7f) << uint(7*i)
		if b&0x80 == 0 {
			return value, i + 1, nil
		}
	}
	return 0, 0, errors.New("varuint32 is longer than 5 bytes")
}

func encodeVaruint32(value uint32) []byte {
	var out []byte
	for {
		b := byte(value & 0x7f)
		value >>= 7
		if value != 0 {
			b |= 0x80
		}
		out = append(out, b)
		if value == 0 {
			return out
		}
	}
}
