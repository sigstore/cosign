// Copyright 2022 The Sigstore Authors.
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

package cosign

import (
	"crypto"
	"errors"
	"hash"
	"io"
	"io/fs"
	"os"
)

const (
	DefaultMaxWorkers int = 10
)

func FileExists(filename string) (bool, error) {
	info, err := os.Stat(filename)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return !info.IsDir(), nil
}

// HashReader hashes while it reads.
type HashReader struct {
	r  io.Reader
	h  hash.Hash
	ch crypto.Hash
	b  *bytesHash
}

func NewHashReader(r io.Reader, ch crypto.Hash) HashReader {
	if ch == crypto.Hash(0) {
		b := &bytesHash{}
		return HashReader{
			r:  io.TeeReader(r, b),
			ch: ch,
			b:  b,
		}
	}
	h := ch.New()
	return HashReader{
		r:  io.TeeReader(r, h),
		h:  h,
		ch: ch,
	}
}

// Read implements io.Reader.
func (h *HashReader) Read(p []byte) (n int, err error) { return h.r.Read(p) }

// Sum implements hash.Hash.
func (h *HashReader) Sum(p []byte) []byte {
	if h.ch == crypto.Hash(0) {
		if h.b == nil {
			return append(p, []byte{}...)
		}
		return h.b.Sum(p)
	}
	return h.h.Sum(p)
}

// Reset implements hash.Hash.
func (h *HashReader) Reset() {
	if h.ch == crypto.Hash(0) {
		if h.b == nil {
			return
		}
		h.b.Reset()
		return
	}
	h.h.Reset()
}

// Size implements hash.Hash.
func (h *HashReader) Size() int {
	if h.ch == crypto.Hash(0) {
		if h.b == nil {
			return 0
		}
		return h.b.Size()
	}
	return h.h.Size()
}

// BlockSize implements hash.Hash.
func (h *HashReader) BlockSize() int {
	if h.ch == crypto.Hash(0) {
		if h.b == nil {
			return 1
		}
		return h.b.BlockSize()
	}
	return h.h.BlockSize()
}

// Write implements hash.Hash
func (h *HashReader) Write(p []byte) (int, error) { return 0, errors.New("not implemented") } //nolint: revive

// HashFunc implements cosign.NamedHash
func (h *HashReader) HashFunc() crypto.Hash { return h.ch }

type bytesHash struct {
	buf []byte
}

func (b *bytesHash) Write(p []byte) (int, error) {
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *bytesHash) Sum(p []byte) []byte {
	return append(p, b.buf...)
}

func (b *bytesHash) Reset() {
	b.buf = nil
}

func (b *bytesHash) Size() int {
	return len(b.buf)
}

func (b *bytesHash) BlockSize() int {
	return 1
}
