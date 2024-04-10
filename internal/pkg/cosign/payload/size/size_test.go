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

package payload

import (
	"testing"
)

func TestCheckSize(t *testing.T) {
	tests := []struct {
		name    string
		input   uint64
		setting string
		wantErr bool
	}{
		{
			name:    "size is within default limit",
			input:   1000,
			wantErr: false,
		},
		{
			name:    "size exceeds default limit",
			input:   200000000,
			wantErr: true,
		},
		{
			name:    "size is within overridden limit (bytes)",
			input:   1000,
			setting: "1024",
			wantErr: false,
		},
		{
			name:    "size is exceeds overridden limit (bytes)",
			input:   2000,
			setting: "1024",
			wantErr: true,
		},
		{
			name:    "size is within overridden limit (megabytes, short form)",
			input:   1999999,
			setting: "2M",
			wantErr: false,
		},
		{
			name:    "size exceeds overridden limit (megabytes, short form)",
			input:   2000001,
			setting: "2M",
			wantErr: true,
		},
		{
			name:    "size is within overridden limit (megabytes, long form)",
			input:   1999999,
			setting: "2MB",
			wantErr: false,
		},
		{
			name:    "size exceeds overridden limit (megabytes, long form)",
			input:   2000001,
			setting: "2MB",
			wantErr: true,
		},
		{
			name:    "size is within overridden limit (mebibytes)",
			input:   2097151,
			setting: "2MiB",
			wantErr: false,
		},
		{
			name:    "size exceeds overridden limit (mebibytes)",
			input:   2097153,
			setting: "2MiB",
			wantErr: true,
		},
		{
			name:    "size is negative results in default",
			input:   5121,
			setting: "-5KiB",
			wantErr: false,
		},
		{
			name:    "invalid setting results in default",
			input:   5121,
			setting: "five kilobytes",
			wantErr: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.setting != "" {
				t.Setenv("COSIGN_MAX_ATTACHMENT_SIZE", test.setting)
			}
			got := CheckSize(test.input)
			if (got != nil) != (test.wantErr) {
				t.Errorf("CheckSize() = %v, expected %v", got, test.wantErr)
			}
		})
	}
}
