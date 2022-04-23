//
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

package policy

import (
	"context"
	"strings"
	"testing"
)

const (
	customAttestation = `
	{
		"_type": "https://in-toto.io/Statement/v0.1",
		"predicateType": "cosign.sigstore.dev/attestation/v1",
		"subject": [
		  {
			"name": "registry.local:5000/cosigned/demo",
			"digest": {
			  "sha256": "416cc82c76114b1744ea58bcbf2f411a0f2de4b0456703bf1bb83d33656951bc"
			}
		  }
		],
		"predicate": {
		  "Data": "foobar e2e test",
		  "Timestamp": "2022-04-20T18:17:19Z"
		}
	  }`

	vulnAttestation = `
	{
		"_type": "https://in-toto.io/Statement/v0.1",
		"predicateType": "cosign.sigstore.dev/attestation/vuln/v1",
		"subject": [
		  {
			"name": "registry.local:5000/cosigned/demo",
			"digest": {
			  "sha256": "416cc82c76114b1744ea58bcbf2f411a0f2de4b0456703bf1bb83d33656951bc"
			}
		  }
		],
		"predicate": {
		  "invocation": {
			"parameters": null,
			"uri": "invocation.example.com/cosign-testing",
			"event_id": "",
			"builder.id": ""
		  },
		  "scanner": {
			"uri": "fakescanner.example.com/cosign-testing",
			"version": "",
			"db": {
			  "uri": "",
			  "version": ""
			},
			"result": null
		  },
		  "metadata": {
			"scanStartedOn": "2022-04-12T00:00:00Z",
			"scanFinishedOn": "2022-04-12T00:10:00Z"
		  }
		}
	  }`

	// TODO(vaikas): Enable tests once we sort this out.
	// cipAttestation = "authorityMatches:{\"key-att\":{\"signatures\":null,\"attestations\":{\"custom-match-predicate\":[{\"subject\":\"PLACEHOLDER\",\"issuer\":\"PLACEHOLDER\"}]}},\"key-signature\":{\"signatures\":[{\"subject\":\"PLACEHOLDER\",\"issuer\":\"PLACEHOLDER\"}],\"attestations\":null},\"keyless-att\":{\"signatures\":null,\"attestations\":{\"custom-keyless\":[{\"subject\":\"PLACEHOLDER\",\"issuer\":\"PLACEHOLDER\"}]}},\"keyless-signature\":{\"signatures\":[{\"subject\":\"PLACEHOLDER\",\"issuer\":\"PLACEHOLDER\"}],\"attestations\":null}}"
)

func TestEvalPolicy(t *testing.T) {
	// TODO(vaikas): Consider moving the attestations/cue files into testdata
	// directory.
	tests := []struct {
		name       string
		json       string
		policyType string
		policyFile string
		wantErr    bool
		wantErrSub string
	}{{
		name:       "custom attestation, mismatched predicateType",
		json:       customAttestation,
		policyType: "cue",
		policyFile: `predicateType: "cosign.sigstore.dev/attestation/vuln/v1"`,
		wantErr:    true,
		wantErrSub: `conflicting values "cosign.sigstore.dev/attestation/v1" and "cosign.sigstore.dev/attestation/vuln/v1"`,
	}, {
		name:       "custom attestation, predicateType and data checks out",
		json:       customAttestation,
		policyType: "cue",
		policyFile: `predicateType: "cosign.sigstore.dev/attestation/v1"
		predicate: Data: "foobar e2e test"`,
	}, {
		name:       "custom attestation, data mismatch",
		json:       customAttestation,
		policyType: "cue",
		policyFile: `predicateType: "cosign.sigstore.dev/attestation/v1"
		predicate: Data: "invalid data here"`,
		wantErr:    true,
		wantErrSub: `predicate.Data: conflicting values "foobar e2e test" and "invalid data here"`,
	}, {
		name:       "vuln attestation, wrong invocation url",
		json:       vulnAttestation,
		policyType: "cue",
		policyFile: `predicateType: "cosign.sigstore.dev/attestation/vuln/v1"
		predicate: invocation: uri: "invocation.example.com/wrong-url-here"`,
		wantErr:    true,
		wantErrSub: `conflicting values "invocation.example.com/cosign-testing" and "invocation.example.com/wrong-url-here"`,
	}, {
		name:       "vuln attestation, checks out",
		json:       vulnAttestation,
		policyType: "cue",
		policyFile: `predicateType: "cosign.sigstore.dev/attestation/vuln/v1"
		predicate: invocation: uri: "invocation.example.com/cosign-testing"`,
	}}
	for _, tc := range tests {
		ctx := context.Background()
		err := EvaluatePolicyAgainstJSON(ctx, tc.name, tc.policyType, tc.policyFile, []byte(tc.json))
		if tc.wantErr {
			if err == nil {
				t.Errorf("Did not get an error, wanted %s", tc.wantErrSub)
			} else if !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Errorf("Unexpected error, want: %s got: %s", tc.wantErrSub, err.Error())
			}
		} else {
			if !tc.wantErr && err != nil {
				t.Errorf("Unexpected error, wanted none, got: %s", err.Error())
			}
		}
	}
}
