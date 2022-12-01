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
	"errors"
	"hash"
	"io"
	"os"
)

func FileExists(filename string) (bool, error) {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return !info.IsDir(), nil
}

// HashReader hashes while it reads.
type HashReader struct {
	r io.Reader
	h hash.Hash
}

func NewHashReader(r io.Reader, h hash.Hash) HashReader {
	return HashReader{
		r: io.TeeReader(r, h),
		h: h,
	}
}

// Read implements io.Reader.
func (h *HashReader) Read(p []byte) (n int, err error) { return h.r.Read(p) }

// Sum implements hash.Hash.
func (h *HashReader) Sum(p []byte) []byte { return h.h.Sum(p) }

// Reset implements hash.Hash.
func (h *HashReader) Reset() { h.h.Reset() }

// Size implements hash.Hash.
func (h *HashReader) Size() int { return h.h.Size() }

// BlockSize implements hash.Hash.
func (h *HashReader) BlockSize() int { return h.h.BlockSize() }

// Write implements hash.Hash
func (h *HashReader) Write(p []byte) (int, error) { return 0, errors.New("not implemented") }
