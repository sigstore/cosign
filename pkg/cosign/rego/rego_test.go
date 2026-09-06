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

package rego

import (
	"fmt"
	"os"
	"testing"
)

const simpleJSONBody = `{
	"_type": "https://in-toto.io/Statement/v0.1",
	"predicateType": "https://slsa.dev/provenance/v0.2"
}`

func TestValidationJSON(t *testing.T) {
	cases := []struct {
		name     string
		jsonBody string
		policy   string
		pass     bool
		errors   []string
	}{
		{
			name:     "passing policy",
			jsonBody: simpleJSONBody,
			policy: `
				package signature

				allow {
					input.predicateType == "https://slsa.dev/provenance/v0.2"
				}
			`,
			pass: true,
		},
		{
			name:     "undefined result due to no matching rules",
			jsonBody: simpleJSONBody,
			policy: `
				package signature

				allow {
					input.predicateType == "https://slsa.dev/provenance/v99.9"
				}
			`,
			pass:   false,
			errors: []string{"result is undefined for query 'data.signature.allow'"},
		},
		{
			name:     "policy query evaluates to false",
			jsonBody: simpleJSONBody,
			policy: `
				package signature

				default allow = false
			`,
			pass:   false,
			errors: []string{"expression value, false, is not true"},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			// Do not use t.TempDir() because rego has issues loading policy files
			// from an absolute path on Windows. Use a relative path instead. See:
			//	https://github.com/open-policy-agent/opa/issues/4521
			policyFileName := "tmp-policy.rego"
			if err := os.WriteFile(policyFileName, []byte(tt.policy), 0644); err != nil {
				t.Fatal(err)
			}
			defer os.Remove(policyFileName)

			if errs := ValidateJSON([]byte(tt.jsonBody), []string{policyFileName}); (errs == nil) != tt.pass {
				t.Fatalf("Unexpected result: %v", errs)
			} else if errs != nil {
				if len(errs) != len(tt.errors) {
					t.Fatalf("Expected %d errors, got %d errors: %v", len(tt.errors), len(errs), errs)
				}
				for i, err := range errs {
					if fmt.Sprintf("%s", err) != tt.errors[i] {
						t.Errorf("Expected error %q, got %q", tt.errors[i], err)
					}
				}
			}
		})
	}
}
