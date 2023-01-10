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
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
)

/*
The following JSON is the payload in valid attestation:
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://cosign.sigstore.dev/attestation/v1",
  "subject": [
    {
      "name": "registry.local:5000/knative/demo",
      "digest": {
        "sha256": "6c6fd6a4115c6e998ff357cd914680931bb9a6c1a7cd5f5cb2f5e1c0932ab6ed"
      }
    }
  ],
  "predicate": {
    "Data": "foobar test attestation",
    "Timestamp": "2022-04-07T19:22:25Z"
  }
}
*/

const (
	validIntotoStatement              = `{"payloadType":"application/vnd.in-toto+json","payload":"eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInByZWRpY2F0ZVR5cGUiOiJjb3NpZ24uc2lnc3RvcmUuZGV2L2F0dGVzdGF0aW9uL3YxIiwic3ViamVjdCI6W3sibmFtZSI6InJlZ2lzdHJ5LmxvY2FsOjUwMDAva25hdGl2ZS9kZW1vIiwiZGlnZXN0Ijp7InNoYTI1NiI6IjZjNmZkNmE0MTE1YzZlOTk4ZmYzNTdjZDkxNDY4MDkzMWJiOWE2YzFhN2NkNWY1Y2IyZjVlMWMwOTMyYWI2ZWQifX1dLCJwcmVkaWNhdGUiOnsiRGF0YSI6ImZvb2JhciB0ZXN0IGF0dGVzdGF0aW9uIiwiVGltZXN0YW1wIjoiMjAyMi0wNC0wN1QxOToyMjoyNVoifX0=","signatures":[{"keyid":"","sig":"MEUCIQC/slGQVpRKgw4Jo8tcbgo85WNG/FOJfxcvQFvTEnG9swIgP4LeOmID+biUNwLLeylBQpAEgeV6GVcEpyG6r8LVnfY="}]}`
	invalidIntotoStatementBadEncoding = `{"payloadType":"application/vnd.in-toto+json","payload":"eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInByZWRpY2F0ZVR5cGUiOiJjb3NpZ24uc2lnc3RvcmUuZGV2L2F0dGVzdGF0aW9uL3YxIiwic3ViamVjdCI6W3sibmFtZSI6InJlZ2lzdHJ5LmxvY2FsOjUwMDAva25hdGl2ZS9kZW1vIiwiZGlnZXN0Ijp7InNoYTI1NiI6IjZjNmZkNmE0MTE1YzZlOTk4ZmYzNTdjZDkxNDY4MDkzMWJiOWE2YzFhN2NkNWY1Y2IyZjVlMWMwOTMyYWI2ZWQifX1dLCJwcmVkaWNhdGUiOnsiRGF0YSI6ImZvb2JhciB0ZXN0IGF0dGVzdGF0aW9uIiwiVGltZXN0YW1wIjoiMjAyMi0wNC0wN1QxOToyMjoyNV=","signatures":[{"keyid":"","sig":"MEUCIQC/slGQVpRKgw4Jo8tcbgo85WNG/FOJfxcvQFvTEnG9swIgP4LeOmID+biUNwLLeylBQpAEgeV6GVcEpyG6r8LVnfY="}]}`
	// Start with valid, but change subject.Digest.sha256 to subject.Digest.999
	validIntotoStatementMissingSubject = `{"payloadType":"application/vnd.in-toto+json","payload":"ewogICJfdHlwZSI6ICJodHRwczovL2luLXRvdG8uaW8vU3RhdGVtZW50L3YwLjEiLAogICJwcmVkaWNhdGVUeXBlIjogImNvc2lnbi5zaWdzdG9yZS5kZXYvYXR0ZXN0YXRpb24vdjEiLAogICJzdWJqZWN0IjogWwogICAgewogICAgICAibmFtZSI6ICJyZWdpc3RyeS5sb2NhbDo1MDAwL2tuYXRpdmUvZGVtbyIsCiAgICAgICJkaWdlc3QiOiB7CiAgICAgICAgIjk5OSI6ICI2YzZmZDZhNDExNWM2ZTk5OGZmMzU3Y2Q5MTQ2ODA5MzFiYjlhNmMxYTdjZDVmNWNiMmY1ZTFjMDkzMmFiNmVkIgogICAgICB9CiAgICB9CiAgXSwKICAicHJlZGljYXRlIjogewogICAgIkRhdGEiOiAiZm9vYmFyIHRlc3QgYXR0ZXN0YXRpb24iLAogICAgIlRpbWVzdGFtcCI6ICIyMDIyLTA0LTA3VDE5OjIyOjI1WiIKICB9Cn0K","signatures":[{"keyid":"","sig":"MEUCIQC/slGQVpRKgw4Jo8tcbgo85WNG/FOJfxcvQFvTEnG9swIgP4LeOmID+biUNwLLeylBQpAEgeV6GVcEpyG6r8LVnfY="}]}`
)

var validDigest = v1.Hash{Algorithm: "sha256", Hex: "6c6fd6a4115c6e998ff357cd914680931bb9a6c1a7cd5f5cb2f5e1c0932ab6ed"}
var invalidDigest = v1.Hash{Algorithm: "sha256", Hex: "6c6fd6a4115c6e998ff357cd914680931bb9a6c1a7cd5f5cb2f5e1c0932xxxxx"}

func Test_IntotoSubjectClaimVerifier(t *testing.T) {
	tests := []struct {
		payload    string
		digest     v1.Hash
		shouldFail bool
	}{{payload: `{"payloadType":"notinttoto"}`, shouldFail: true},
		{payload: `{"payloadType":"notmarshallable}`, shouldFail: true},
		{payload: invalidIntotoStatementBadEncoding, shouldFail: true},
		{payload: validIntotoStatement, shouldFail: true}, // no matching image hash
		{payload: validIntotoStatement, digest: invalidDigest, shouldFail: true},
		{payload: validIntotoStatementMissingSubject, digest: validDigest, shouldFail: true},
		{payload: validIntotoStatement, digest: validDigest, shouldFail: false},
	}
	for _, tc := range tests {
		ociSig, err := static.NewSignature([]byte(tc.payload), "")
		if err != nil {
			t.Fatal("Failed to create static.NewSignature: ", err)
		}
		got := IntotoSubjectClaimVerifier(ociSig, tc.digest, nil)
		if got != nil && !tc.shouldFail {
			t.Error("Expected ClaimVerifier to succeed but failed: ", got)
		}
		if got == nil && tc.shouldFail {
			t.Error("Expected ClaimVerifier to fail but didn't: ")
		}
	}
}
