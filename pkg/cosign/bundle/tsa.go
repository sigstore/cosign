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

// TSABundle holds metadata about timestamp RFC3161 verification data.
type TSABundle struct {
	// SignedRFC3161Timestamp contains a RFC3161 signed timestamp provided by a time-stamping server.
	// Clients MUST verify the hashed message in the message imprint
	// against the signature in the bundle. This is encoded as base64.
	SignedRFC3161Timestamp []byte
}

// TimestampToTSABundle receives a base64 encoded RFC3161 timestamp.
func TimestampToTSABundle(timestampRFC3161 []byte) *TSABundle {
	if timestampRFC3161 != nil {
		return &TSABundle{
			SignedRFC3161Timestamp: timestampRFC3161,
		}
	}
	return nil
}
