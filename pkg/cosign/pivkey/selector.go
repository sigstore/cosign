// Copyright 2026 The Sigstore Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pivkey

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// Selector identifies a PIV card by its YubiKey serial number, the SHA-256
// digest of a slot's PKIX-encoded public key, or both.
type Selector struct {
	Serial    string
	KeySHA256 string
}

type normalizedSelector struct {
	serial    *uint32
	keySHA256 *[32]byte
}

func normalizeSelector(selector Selector) (normalizedSelector, error) {
	var normalized normalizedSelector

	serial := strings.TrimSpace(selector.Serial)
	if serial != "" {
		value, err := strconv.ParseUint(serial, 10, 32)
		if err != nil {
			return normalized, fmt.Errorf("invalid PIV serial %q: must be an unsigned 32-bit decimal number", selector.Serial)
		}
		parsed := uint32(value)
		normalized.serial = &parsed
	}

	fingerprint := strings.TrimSpace(selector.KeySHA256)
	if fingerprint != "" {
		fingerprint = strings.TrimPrefix(strings.ToLower(fingerprint), "sha256:")
		fingerprint = strings.ReplaceAll(fingerprint, ":", "")
		if len(fingerprint) != 64 {
			return normalized, fmt.Errorf("invalid PIV key SHA-256 fingerprint: expected 64 hexadecimal characters")
		}

		decoded, err := hex.DecodeString(fingerprint)
		if err != nil {
			return normalized, fmt.Errorf("invalid PIV key SHA-256 fingerprint: %w", err)
		}
		var parsed [32]byte
		copy(parsed[:], decoded)
		normalized.keySHA256 = &parsed
	}

	return normalized, nil
}
