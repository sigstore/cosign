//
// Copyright 2021 The Sigstore Authors.
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

package static

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

func TestNewFile(t *testing.T) {
	payload := "this is the content!"
	f, err := NewFile([]byte(payload), WithLayerMediaType("foo"), WithAnnotations(map[string]string{"foo": "bar"}))
	if err != nil {
		t.Fatalf("NewFile() = %v", err)
	}

	timestampedFile, err := NewFile([]byte(payload), WithLayerMediaType("foo"), WithAnnotations(map[string]string{"foo": "bar"}), WithRecordCreationTimestamp(true))

	if err != nil {
		t.Fatalf("NewFile() = %v", err)
	}

	layers, err := f.Layers()
	if err != nil {
		t.Fatalf("Layers() = %v", err)
	} else if got, want := len(layers), 1; got != want {
		t.Fatalf("len(Layers()) = %d, wanted %d", got, want)
	}
	l := layers[0]

	t.Run("check size", func(t *testing.T) {
		wantSize := int64(len(payload))
		gotSize, err := l.Size()
		if err != nil {
			t.Fatalf("Size() = %v", err)
		}
		if gotSize != wantSize {
			t.Errorf("Size() = %d, wanted %d", gotSize, wantSize)
		}
	})

	t.Run("check media type", func(t *testing.T) {
		wantMT := types.MediaType("foo")
		gotMT, err := f.FileMediaType()
		if err != nil {
			t.Fatalf("MediaType() = %v", err)
		}
		if gotMT != wantMT {
			t.Errorf("MediaType() = %s, wanted %s", gotMT, wantMT)
		}
	})

	t.Run("check hashes", func(t *testing.T) {
		wantHash, _, err := v1.SHA256(strings.NewReader(payload))
		if err != nil {
			t.Fatalf("SHA256() = %v", err)
		}

		gotDigest, err := l.Digest()
		if err != nil {
			t.Fatalf("Digest() = %v", err)
		}
		if !cmp.Equal(gotDigest, wantHash) {
			t.Errorf("Digest = %s", cmp.Diff(gotDigest, wantHash))
		}

		gotDiffID, err := l.DiffID()
		if err != nil {
			t.Fatalf("DiffID() = %v", err)
		}
		if !cmp.Equal(gotDiffID, wantHash) {
			t.Errorf("DiffID = %s", cmp.Diff(gotDiffID, wantHash))
		}
	})

	t.Run("check content", func(t *testing.T) {
		comp, err := l.Compressed()
		if err != nil {
			t.Fatalf("Compressed() = %v", err)
		}
		defer comp.Close()
		compContent, err := io.ReadAll(comp)
		if err != nil {
			t.Fatalf("ReadAll() = %v", err)
		}
		if got, want := string(compContent), payload; got != want {
			t.Errorf("Compressed() = %s, wanted %s", got, want)
		}

		uncomp, err := l.Uncompressed()
		if err != nil {
			t.Fatalf("Uncompressed() = %v", err)
		}
		defer uncomp.Close()
		uncompContent, err := io.ReadAll(uncomp)
		if err != nil {
			t.Fatalf("ReadAll() = %v", err)
		}
		if got, want := string(uncompContent), payload; got != want {
			t.Errorf("Uncompressed() = %s, wanted %s", got, want)
		}

		gotPayload, err := f.Payload()
		if err != nil {
			t.Fatalf("Payload() = %v", err)
		}
		if got, want := string(gotPayload), payload; got != want {
			t.Errorf("Payload() = %s, wanted %s", got, want)
		}
	})

	t.Run("check date", func(t *testing.T) {
		fileCfg, err := f.ConfigFile()
		if err != nil {
			t.Fatalf("ConfigFile() = %v", err)
		}
		if !fileCfg.Created.Time.IsZero() {
			t.Errorf("Date of Signature was not Zero")
		}
		tsCfg, err := timestampedFile.ConfigFile()
		if err != nil {
			t.Fatalf("ConfigFile() = %v", err)
		}
		if tsCfg.Created.Time.IsZero() {
			t.Errorf("Date of Signature was Zero")
		}
	})

	t.Run("check annotations", func(t *testing.T) {
		m, err := f.Manifest()
		if err != nil {
			t.Fatalf("Manifest() = %v", err)
		}
		gotAnnotations := m.Annotations
		if got, want := gotAnnotations["foo"], "bar"; got != want {
			t.Errorf("Annotations = %s, wanted %s", got, want)
		}
	})

	t.Run("huge file payload", func(t *testing.T) {
		// default limit
		f := file{
			layer: &mockLayer{200000000},
		}
		want := errors.New("size of layer (200000000) exceeded the limit (134217728)")
		_, err = f.Payload()
		if err == nil || want.Error() != err.Error() {
			t.Errorf("Payload() = %v, wanted %v", err, want)
		}
		// override limit
		t.Setenv("COSIGN_MAX_ATTACHMENT_SIZE", "512MiB")
		_, err = f.Payload()
		if err != nil {
			t.Errorf("Payload() = %v, wanted nil", err)
		}
	})
}

type mockLayer struct {
	size int64
}

func (m *mockLayer) Size() (int64, error) {
	return m.size, nil
}

func (m *mockLayer) Uncompressed() (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("data")), nil
}

func (m *mockLayer) Digest() (v1.Hash, error)            { panic("not implemented") }
func (m *mockLayer) DiffID() (v1.Hash, error)            { panic("not implemented") }
func (m *mockLayer) Compressed() (io.ReadCloser, error)  { panic("not implemented") }
func (m *mockLayer) MediaType() (types.MediaType, error) { panic("not implemented") }
