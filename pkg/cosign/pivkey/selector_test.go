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
	"strings"
	"testing"
)

func TestNormalizeSelector(t *testing.T) {
	tests := []struct {
		name        string
		selector    Selector
		wantSerial  uint32
		wantKeyHash string
		wantErr     string
	}{
		{
			name:       "serial",
			selector:   Selector{Serial: "12345678"},
			wantSerial: 12345678,
		},
		{
			name:        "prefixed and colon separated fingerprint",
			selector:    Selector{KeySHA256: "SHA256:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff"},
			wantKeyHash: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
		},
		{
			name:     "invalid serial",
			selector: Selector{Serial: "-1"},
			wantErr:  "unsigned 32-bit decimal number",
		},
		{
			name:     "serial overflow",
			selector: Selector{Serial: "4294967296"},
			wantErr:  "unsigned 32-bit decimal number",
		},
		{
			name:     "short fingerprint",
			selector: Selector{KeySHA256: "abcd"},
			wantErr:  "expected 64 hexadecimal characters",
		},
		{
			name:     "non-hex fingerprint",
			selector: Selector{KeySHA256: strings.Repeat("z", 64)},
			wantErr:  "invalid byte",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			normalized, err := normalizeSelector(test.selector)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("normalizeSelector() error = %v, want error containing %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeSelector() error = %v", err)
			}
			if test.wantSerial != 0 {
				if normalized.serial == nil || *normalized.serial != test.wantSerial {
					t.Fatalf("serial = %v, want %d", normalized.serial, test.wantSerial)
				}
			}
			if test.wantKeyHash != "" {
				if normalized.keySHA256 == nil || hex.EncodeToString(normalized.keySHA256[:]) != test.wantKeyHash {
					t.Fatalf("key SHA-256 = %v, want %s", normalized.keySHA256, test.wantKeyHash)
				}
			}
		})
	}
}
