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

package bundle

import (
	"testing"

	"github.com/sigstore/rekor/pkg/generated/models"
)

func TestMakeProtobufBundle(t *testing.T) {
	testCases := []struct {
		name           string
		hint           string
		rawCert        []byte
		rekorEntry     *models.LogEntryAnon
		timestampBytes []byte
	}{
		{
			name:           "hint with timestamp",
			hint:           "asdf",
			rawCert:        []byte{},
			rekorEntry:     nil,
			timestampBytes: []byte("timestamp"),
		},
		{
			name:           "only cert",
			hint:           "",
			rawCert:        []byte("cert stuff"),
			rekorEntry:     nil,
			timestampBytes: []byte{},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			bundle, err := MakeProtobufBundle(tc.hint, tc.rawCert, tc.rekorEntry, tc.timestampBytes)
			if err != nil {
				t.Errorf("unexpected err %s", err)
			}
			if tc.hint != "" && bundle.VerificationMaterial.GetPublicKey() == nil {
				t.Errorf("Verification material should be public key")
			}
			if len(tc.rawCert) > 0 && bundle.VerificationMaterial.GetCertificate() == nil {
				t.Errorf("Verification material should be certificate")
			}
			if len(tc.timestampBytes) > 0 && bundle.VerificationMaterial.GetTimestampVerificationData() == nil {
				t.Errorf("Verification material should have timestamp")
			}
		})
	}
}
