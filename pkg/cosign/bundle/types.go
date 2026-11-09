// Copyright 2026 The Sigstore Authors.
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

import "github.com/sigstore/cosign/v3/pkg/cosign/bundle/types"

// The bundle metadata types live in the dependency-free types package so
// that pkg/oci can use them without importing the signing code in this
// package. They are aliased here for compatibility.

type (
	RekorBundle      = types.RekorBundle
	RekorPayload     = types.RekorPayload
	RFC3161Timestamp = types.RFC3161Timestamp
)

const BundleV03MediaType = types.BundleV03MediaType

// TimestampToRFC3161Timestamp receives a base64 encoded RFC3161 timestamp.
func TimestampToRFC3161Timestamp(timestampRFC3161 []byte) *RFC3161Timestamp {
	return types.TimestampToRFC3161Timestamp(timestampRFC3161)
}
