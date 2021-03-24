// Copyright 2021 The Rekor Authors
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

package gcp

import "testing"

func TestParseReference(t *testing.T) {
	tests := []struct {
		in             string
		wantProjectID  string
		wantLocationID string
		wantKeyRing    string
		wantKeyName    string
		wantErr        bool
	}{
		{
			in:             "gcpkms://projects/pp/locations/ll/keyRings/rr/cryptoKeys/kk",
			wantProjectID:  "pp",
			wantLocationID: "ll",
			wantKeyRing:    "rr",
			wantKeyName:    "kk",
			wantErr:        false,
		},
		{
			in:      "gcpkms://projects/p1/p2/locations/l1/l2/keyRings/r1/r2/cryptoKeys/k1/k2",
			wantErr: true,
		},
		{
			in:      "foo://bar",
			wantErr: true,
		},
		{
			in:      "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			gotProjectID, gotLocationID, gotKeyRing, gotKeyName, err := parseReference(tt.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseReference() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotProjectID != tt.wantProjectID {
				t.Errorf("parseReference() gotProjectID = %v, want %v", gotProjectID, tt.wantProjectID)
			}
			if gotLocationID != tt.wantLocationID {
				t.Errorf("parseReference() gotLocationID = %v, want %v", gotLocationID, tt.wantLocationID)
			}
			if gotKeyRing != tt.wantKeyRing {
				t.Errorf("parseReference() gotKeyRing = %v, want %v", gotKeyRing, tt.wantKeyRing)
			}
			if gotKeyName != tt.wantKeyName {
				t.Errorf("parseReference() gotKeyName = %v, want %v", gotKeyName, tt.wantKeyName)
			}
		})
	}
}
