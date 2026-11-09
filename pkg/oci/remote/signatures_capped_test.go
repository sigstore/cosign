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

package remote

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"strings"
	"testing"

	payloadsize "github.com/sigstore/cosign/v3/internal/pkg/cosign/payload/size"
	"github.com/sigstore/cosign/v3/pkg/cosign/env"
)

func TestReadCappedWithinLimit(t *testing.T) {
	t.Setenv(env.VariableMaxAttachmentSize.String(), "1024")

	got, err := readCapped(strings.NewReader(strings.Repeat("a", 1024)))
	if err != nil {
		t.Fatalf("readCapped() returned an unexpected error: %v", err)
	}
	if len(got) != 1024 {
		t.Errorf("readCapped() returned %d bytes, wanted 1024", len(got))
	}
}

func TestReadCappedRejectsOversizedPayload(t *testing.T) {
	t.Setenv(env.VariableMaxAttachmentSize.String(), "1024")

	_, err := readCapped(strings.NewReader(strings.Repeat("a", 1025)))
	if err == nil {
		t.Fatal("readCapped() accepted a payload one byte over the limit")
	}
	var sizeErr *payloadsize.MaxLayerSizeExceeded
	if !errors.As(err, &sizeErr) {
		t.Errorf("readCapped() returned %T, wanted *payloadsize.MaxLayerSizeExceeded", err)
	}
}

// A bundle layer is read through Uncompressed, so the size a registry declares
// for the layer does not bound the result. This is the case the declared-size
// check on its own cannot catch: a small compressed blob that inflates well
// past the maximum.
func TestReadCappedRejectsDecompressionBomb(t *testing.T) {
	t.Setenv(env.VariableMaxAttachmentSize.String(), "1M")

	const uncompressed = 64 << 20 // 64MiB of zeroes, comfortably over the 1MiB cap

	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := io.Copy(zw, io.LimitReader(zeroReader{}, uncompressed)); err != nil {
		t.Fatalf("building the gzip stream failed: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("closing the gzip writer failed: %v", err)
	}

	compressedSize := buf.Len()
	if uint64(compressedSize) > payloadsize.MaxSize() {
		t.Fatalf("the compressed stream is %d bytes, which the declared-size check would already reject; this test needs it under the cap", compressedSize)
	}

	zr, err := gzip.NewReader(&buf)
	if err != nil {
		t.Fatalf("opening the gzip stream failed: %v", err)
	}
	defer zr.Close()

	_, err = readCapped(zr)
	if err == nil {
		t.Fatalf("readCapped() consumed a stream inflating from %d bytes to %d", compressedSize, uncompressed)
	}
	var sizeErr *payloadsize.MaxLayerSizeExceeded
	if !errors.As(err, &sizeErr) {
		t.Errorf("readCapped() returned %T, wanted *payloadsize.MaxLayerSizeExceeded", err)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}
