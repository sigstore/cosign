//
// Copyright 2021 The Sigstore Authors.
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

package cue

import (
	"fmt"
	"os"

	"testing"
)

var cueJSONAttestationsBody = `
{
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
		  "key1": [
			{
			  "subject": "PLACEHOLDER",
			  "issuer": "PLACEHOLDER"
			}
		  ],
		  "key2": [
			{
			  "subject": "PLACEHOLDER",
			  "issuer": "PLACEHOLDER"
			}
		  ]
		}
	  },
	  "keylesssignature": {
		"signatures": [
		  {
			"subject": "PLACEHOLDER",
			"issuer": "PLACEHOLDER"
		  }
		],
		"attestations": null
	  }
	}
  }
`

var cueJSONSampleBody = `{
    "seq": [
        1, 2, 3, {
            "a": 1,
            "b": 2
        }
    ],
    "a": {"b": {"c": 3}},
    "b": {
        "x": 0,
        "y": 1,
        "z": 2
    }
}`

func TestValidationJSON(t *testing.T) {
	cases := []struct {
		name     string
		jsonBody string
		policy   string
		pass     bool
		errorMsg string
	}{
		{
			name:     "passing policy",
			jsonBody: cueJSONSampleBody,
			policy: `
				package test

				seq: [
					1, 2, 3, {
						a: 1
						b: 2
					}
				]
				a: b: c: 3
				b: {
					x: 0
					y: 1
					z: 2
				}
			`,
			pass: true,
		},
		{
			name:     "passing result due to matching rules",
			jsonBody: cueJSONAttestationsBody,
			policy: `
				package test
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
						attestations: struct.MinFields(2) & struct.MaxFields(2)
					},
					keylesssignature: {
						signatures: list.MaxItems(1) & list.MinItems(1)
					}
				}
			`,
			pass: true,
		},
		{
			name:     "policy query evaluates to false signatures array min items",
			jsonBody: cueJSONAttestationsBody,
			policy: `
				package test
				import "list"

				authorityMatches: {
					keysignature: {
					  signatures: list.MaxItems(2) & list.MinItems(2)
					}
				}
			`,
			pass:     false,
			errorMsg: "authorityMatches.keysignature.signatures: invalid value [{subject:\"PLACEHOLDER\",issuer:\"PLACEHOLDER\"}] (does not satisfy list.MinItems(2))",
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			policyFileName := "tmp-policy.cue"
			if err := os.WriteFile(policyFileName, []byte(tt.policy), 0644); err != nil {
				t.Fatal(err)
			}
			defer os.Remove(policyFileName)

			if err := ValidateJSON([]byte(tt.jsonBody), []string{policyFileName}); (err == nil) != tt.pass {
				t.Fatalf("Unexpected result: %v", err)
			} else if err != nil {
				if fmt.Sprintf("%s", err) != tt.errorMsg {
					t.Errorf("Expected error %q, got %q", tt.errorMsg, err)
				}
			}
		})
	}
}
