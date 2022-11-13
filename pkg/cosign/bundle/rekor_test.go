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

package bundle

import (
	"encoding/base64"
	"reflect"
	"testing"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/sigstore/rekor/pkg/generated/models"
)

func TestRekorBundle(t *testing.T) {
	testCases := []struct {
		name                string
		logEntry            *models.LogEntryAnon
		expectedRekorBundle *RekorBundle
	}{{
		name: "tlog entry without verification - nil bundle",
		logEntry: &models.LogEntryAnon{
			Body:           base64.StdEncoding.EncodeToString([]byte("TEST")),
			IntegratedTime: swag.Int64(time.Now().Unix()),
			LogIndex:       swag.Int64(0),
			LogID:          swag.String("c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"),
		},
		expectedRekorBundle: nil,
	}, {
		name: "tlog entry with verification",
		logEntry: &models.LogEntryAnon{
			Body:           base64.StdEncoding.EncodeToString([]byte("TEST")),
			IntegratedTime: swag.Int64(time.Now().Unix()),
			LogIndex:       swag.Int64(0),
			LogID:          swag.String("c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"),
			Verification: &models.LogEntryAnonVerification{
				SignedEntryTimestamp: strfmt.Base64([]byte("signature")),
				InclusionProof: &models.InclusionProof{
					LogIndex: swag.Int64(0),
					TreeSize: swag.Int64(1),
					RootHash: swag.String("TEST"),
					Hashes:   []string{},
				},
			},
		},
		expectedRekorBundle: &RekorBundle{
			Payload: RekorPayload{
				Body:           base64.StdEncoding.EncodeToString([]byte("TEST")),
				IntegratedTime: time.Now().Unix(),
				LogIndex:       0,
				LogID:          "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
			},
			SignedEntryTimestamp: strfmt.Base64([]byte("signature")),
		},
	}}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gotBundle := EntryToBundle(tc.logEntry)
			if !reflect.DeepEqual(gotBundle, tc.expectedRekorBundle) {
				t.Errorf("EntryToBundle returned %v, wanted %v", gotBundle, tc.expectedRekorBundle)
			}
		})
	}
}
