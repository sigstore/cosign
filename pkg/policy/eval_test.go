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
			"name": "registry.local:5000/policy-controller/demo",
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
			"name": "registry.local:5000/policy-controller/demo",
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

	cipAttestation = `{
		"authorityMatches": {
		  "keyatt": {
			"signatures": null,
			"attestations": {
			  "vuln-key": [
				{
				  "subject": "PLACEHOLDER",
				  "issuer": "PLACEHOLDER"
				}
			  ]
			}
		  },
		  "keysignature": {
			"signatures": [
			  {
				"subject": "PLACEHOLDER",
				"issuer": "PLACEHOLDER"
			  }
			],
			"attestations": null
		  },
		  "keylessatt": {
			"signatures": null,
			"attestations": {
			  "custom-keyless": [
				{
				  "subject": "PLACEHOLDER",
				  "issuer": "PLACEHOLDER"
				}
			  ]
			}
		  }
		}
	  }`

	cipAttestationMissingAttestations = `{
		"authorityMatches": {
		  "keyatt": {
			"signatures": null,
			"attestations": {
			  "custom-match-predicate": [
				{
				  "subject": "",
				  "issuer": ""
				}
			  ]
			}
		  },
		  "keylesssignature": {
			"signatures": [
			  {
				"subject": "https://kubernetes.io/namespaces/default/serviceaccounts/default",
				"issuer": "https://kubernetes.default.svc"
			  }
			],
			"attestations": null
		  },
		  "keysignature": {
			"signatures": [
			  {
				"subject": "",
				"issuer": ""
			  }
			],
			"attestations": null
		  },
		}
	  }`

	// This cipPolicy should reject the above but clearly it's wrong and I
	// don't understand enough to know what's wrong with it.
	cipPolicy = `package sigstore
	import (
	  "list"
	  "strings"
	  "struct"
	)

	authorityMatches: {
	  keyatt: {
		attestations: struct.MaxFields(1) & struct.MinFields(1)
	  },
	  keysignature: {
		signatures: list.MaxItems(1) & list.MinItems(1)
	  },
	  keylessatt: {
		attestations: {
		  vulnkeyless: [...{
			subject: string
			if subject != "https://kubernetes.io/namespaces/default/serviceaccounts/default" {
				  expectedError: "no error",
				  err: strings.Join(["Error: subject does not match", subject], " ")
				  expectedError: err
			}
		  }]
		}
	  }
	  keylesssignature: {
		signatures: list.MaxItems(1) & list.MinItems(1)
	  }
	}`
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
	}, {
		name:       "cluster image policy main policy, checks out",
		json:       cipAttestation,
		policyType: "cue",
		policyFile: `package sigstore
		import "struct"
		import "list"
		authorityMatches: {
		  keyatt: {
			attestations: struct.MaxFields(1) & struct.MinFields(1)
		  },
		  keysignature: {
			signatures: list.MaxItems(1) & list.MinItems(1)
		  },
		  keylessatt: {
			attestations: struct.MaxFields(1) & struct.MinFields(1)
		  },
		  keylesssignature: {
			signatures: list.MaxItems(1) & list.MinItems(1)
		  }
		}`,
	}, {
		name:       "cluster image policy main policy, fails",
		json:       cipAttestation,
		policyType: "cue",
		wantErr:    true,
		wantErrSub: `failed evaluating cue policy for cluster image policy main policy, fails: failed to evaluate the policy with error: authorityMatches.keylessattMinAttestations: conflicting values 2 and "Error" (mismatched types int and string)`,
		policyFile: `package sigstore
		import "struct"
		import "list"
		authorityMatches: {
		  keyatt: {
			attestations: struct.MaxFields(1) & struct.MinFields(1)
		  },
		  keysignature: {
			signatures: list.MaxItems(1) & list.MinItems(1)
		  },
		  if( len(authorityMatches.keylessatt.attestations) < 2) {
			keylessattMinAttestations: 2
			keylessattMinAttestations: "Error"
		  },
		  keylesssignature: {
			signatures: list.MaxItems(1) & list.MinItems(1)
		  }
		}`,
	}, {
		name:       "cluster image policy main policy with no attestations, fails",
		json:       cipAttestationMissingAttestations,
		policyType: "cue",
		wantErr:    true,
		wantErrSub: `failed evaluating cue policy for cluster image policy main policy, fails: failed to evaluate the policy with error: authorityMatches.keylessattMinAttestations: conflicting values 2 and "Error" (mismatched types int and string)`,
		policyFile: cipPolicy,
	}, {
		name:       "Rego cluster image policy main policy, checks out",
		json:       cipAttestation,
		policyType: "rego",
		policyFile: `package sigstore
			default isCompliant = false
			isCompliant {
				attestationsKeylessATT := input.authorityMatches.keylessatt.attestations
				count(attestationsKeylessATT) == 1
				attestationsKeyATT := input.authorityMatches.keyatt.attestations
				count(attestationsKeyATT) == 1
				keySignature := input.authorityMatches.keysignature.signatures
				count(keySignature) == 1
			}`,
	}, {
		name:       "Rego cluster image policy main policy, fails",
		json:       cipAttestation,
		policyType: "rego",
		wantErr:    true,
		wantErrSub: `failed evaluating rego policy for type Rego cluster image policy main policy, fails: policy is not compliant for query 'isCompliant = data.sigstore.isCompliant'`,
		policyFile: `package sigstore
			default isCompliant = false
			isCompliant {
			    attestationsKeylessATT := input.authorityMatches.keylessatt.attestations
				count(attestationsKeylessATT) == 2
				attestationsKeyATT := input.authorityMatches.keyatt.attestations
				count(attestationsKeyATT) == 1
				keySignature := input.authorityMatches.keysignature.signatures
				count(keySignature) == 1
			}`,
	}, {}}
	for _, tc := range tests {
		ctx := context.Background()
		err := EvaluatePolicyAgainstJSON(ctx, tc.name, tc.policyType, tc.policyFile, []byte(tc.json))
		if tc.wantErr {
			if err == nil {
				t.Errorf("%q did not get an error, wanted %s", tc.name, tc.wantErrSub)
			} else if !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Errorf("%q unexpected error, want: %s got: %s", tc.name, tc.wantErrSub, err.Error())
			}
		} else {
			if !tc.wantErr && err != nil {
				t.Errorf("%q unexpected error, wanted none, got: %s", tc.name, err.Error())
			}
		}
	}
}
