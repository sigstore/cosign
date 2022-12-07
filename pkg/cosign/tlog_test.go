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
	"context"
	"testing"
)

func TestGetRekorPubKeys(t *testing.T) {
	keys, err := GetRekorPubs(context.Background())
	if err != nil {
		t.Errorf("Unexpected error calling GetRekorPubs, expected nil: %v", err)
	}
	if len(keys.Keys) == 0 {
		t.Errorf("expected 1 or more keys, got 0")
	}
	// check that the mapping of key digest to key is correct
	for logID, key := range keys.Keys {
		expectedLogID, err := getLogID(key.PubKey)
		if err != nil {
			t.Fatalf("unexpected error generated log ID: %v", err)
		}
		if logID != expectedLogID {
			t.Fatalf("key digests are not equal")
		}
	}
}

func TestExpectedRekorResponse(t *testing.T) {
	validUUID := "f794467401d57241b7903737211c721cb3315648d077a9f02ceefb6e404a05de"
	validUUID1 := "7794467401d57241b7903737211c721cb3315648d077a9f02ceefb6e404a05de"

	validTreeID := "0FFFFFFFFFFFFFFF"
	validTreeID1 := "3315648d077a9f02"
	invalidTreeID := "0000000000000000"
	tests := []struct {
		name         string
		requestUUID  string
		responseUUID string
		treeID       string
		wantErr      bool
	}{
		{
			name:         "valid match with request & response entry UUID",
			requestUUID:  validTreeID + validUUID,
			responseUUID: validTreeID + validUUID,
			treeID:       validTreeID,
			wantErr:      false,
		},
		// The following is the current typical Rekor behavior.
		{
			name:         "valid match with request entry UUID",
			requestUUID:  validTreeID + validUUID,
			responseUUID: validUUID,
			treeID:       validTreeID,
			wantErr:      false,
		},
		{
			name:         "valid match with request UUID",
			requestUUID:  validUUID,
			responseUUID: validUUID,
			treeID:       validTreeID,
			wantErr:      false,
		},
		{
			name:         "valid match with response entry UUID",
			requestUUID:  validUUID,
			responseUUID: validTreeID + validUUID,
			treeID:       validTreeID,
			wantErr:      false,
		},
		{
			name:         "mismatch uuid with response tree id",
			requestUUID:  validUUID,
			responseUUID: validTreeID + validUUID1,
			treeID:       validTreeID,
			wantErr:      true,
		},
		{
			name:         "mismatch uuid with request tree id",
			requestUUID:  validTreeID + validUUID1,
			responseUUID: validUUID,
			treeID:       validTreeID,
			wantErr:      true,
		},
		{
			name:         "mismatch tree id",
			requestUUID:  validTreeID + validUUID,
			responseUUID: validUUID,
			treeID:       validTreeID1,
			wantErr:      true,
		},
		{
			name:         "invalid response tree id",
			requestUUID:  validTreeID + validUUID,
			responseUUID: invalidTreeID + validUUID,
			treeID:       invalidTreeID,
			wantErr:      true,
		},
		{
			name:         "invalid request tree id",
			requestUUID:  invalidTreeID + validUUID,
			responseUUID: validUUID,
			treeID:       invalidTreeID,
			wantErr:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isExpectedResponseUUID(tt.requestUUID,
				tt.responseUUID, tt.treeID); (got != nil) != tt.wantErr {
				t.Errorf("isExpectedResponseUUID() = %v, want %v", got, tt.wantErr)
			}
		})
	}
}
