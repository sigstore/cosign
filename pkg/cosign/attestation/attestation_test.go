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

package attestation

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestGenerateStatement(t *testing.T) {
	fixedTime := time.Date(2024, 3, 11, 10, 0, 0, 0, time.UTC)
	opts := GenerateOpts{
		Digest: "abcdef123456",
		Repo:   "test-repo",
		Time:   func() time.Time { return fixedTime },
	}

	tests := []struct {
		name      string
		predType  string
		predicate string
		wantJSON  string
	}{
		{
			name:      "custom",
			predType:  "custom",
			predicate: "some data",
			wantJSON:  `{"_type":"https://in-toto.io/Statement/v0.1","subject":[{"name":"test-repo","digest":{"sha256":"abcdef123456"}}],"predicateType":"https://cosign.sigstore.dev/attestation/v1","predicate":{"Data":"some data","Timestamp":"2024-03-11T10:00:00Z"}}`,
		},
		{
			name:      "custom type",
			predType:  "https://example.com/predicate/v1",
			predicate: `{"key":"value"}`,
			wantJSON:  `{"_type":"https://in-toto.io/Statement/v0.1","subject":[{"name":"test-repo","digest":{"sha256":"abcdef123456"}}],"predicateType":"https://example.com/predicate/v1","predicate":{"key":"value"}}`,
		},
		{
			name:      "custom empty string",
			predType:  "custom",
			predicate: "",
			wantJSON:  `{"_type":"https://in-toto.io/Statement/v0.1","subject":[{"name":"test-repo","digest":{"sha256":"abcdef123456"}}],"predicateType":"https://cosign.sigstore.dev/attestation/v1","predicate":{"Data":"","Timestamp":"2024-03-11T10:00:00Z"}}`,
		},
		{
			name:      "spdx string",
			predType:  "spdx",
			predicate: "SPDX-data",

			wantJSON: `{"_type":"https://in-toto.io/Statement/v0.1","subject":[{"name":"test-repo","digest":{"sha256":"abcdef123456"}}],"predicateType":"https://spdx.dev/Document","predicate":"SPDX-data"}`,
		},
		{
			name:      "spdx string multi-line",
			predType:  "spdx",
			predicate: "SPDXVersion: SPDX-2.3\\nDataLicense: CC0-1.0\\nDocumentName: Test",
			wantJSON:  `{"_type":"https://in-toto.io/Statement/v0.1","subject":[{"name":"test-repo","digest":{"sha256":"abcdef123456"}}],"predicateType":"https://spdx.dev/Document","predicate":"SPDXVersion: SPDX-2.3\\nDataLicense: CC0-1.0\\nDocumentName: Test"}`,
		},
		{
			name:      "spdx json",
			predType:  "spdxjson",
			predicate: `{"spdxVersion":"SPDX-2.3"}`,
			wantJSON:  `{"_type":"https://in-toto.io/Statement/v0.1","subject":[{"name":"test-repo","digest":{"sha256":"abcdef123456"}}],"predicateType":"https://spdx.dev/Document","predicate":{"spdxVersion":"SPDX-2.3"}}`,
		},
		{
			name:     "spdx json complex",
			predType: "spdxjson",
			predicate: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"SPDXID": "SPDXRef-DOCUMENT",
				"name": "Test Document",
				"documentNamespace": "http://example.com/spdx/TestDocument",
				"creationInfo": {
					"creators": ["Person: John Doe"],
					"created": "2024-03-11T10:00:00Z"
				}
			}`,
			wantJSON: `{"_type":"https://in-toto.io/Statement/v0.1","subject":[{"name":"test-repo","digest":{"sha256":"abcdef123456"}}],"predicateType":"https://spdx.dev/Document","predicate":{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT","name":"Test Document","documentNamespace":"http://example.com/spdx/TestDocument","creationInfo":{"creators":["Person: John Doe"],"created":"2024-03-11T10:00:00Z"}}}`,
		},
		{
			name:      "cyclonedx",
			predType:  "cyclonedx",
			predicate: `{"bomFormat":"CycloneDX"}`,
			wantJSON:  `{"_type":"https://in-toto.io/Statement/v0.1","subject":[{"name":"test-repo","digest":{"sha256":"abcdef123456"}}],"predicateType":"https://cyclonedx.org/bom","predicate":{"bomFormat":"CycloneDX"}}`,
		},
		{
			name:     "cyclonedx complex",
			predType: "cyclonedx",
			predicate: `{
				"bomFormat": "CycloneDX",
				"specVersion": "1.4",
				"version": 1,
				"metadata": {
					"timestamp": "2024-03-11T10:00:00Z",
					"tools": [
						{
							"vendor": "Test Vendor",
							"name": "Test Tool",
							"version": "1.0.0"
						}
					]
				},
				"components": []
			}`,
			wantJSON: `{"_type":"https://in-toto.io/Statement/v0.1","subject":[{"name":"test-repo","digest":{"sha256":"abcdef123456"}}],"predicateType":"https://cyclonedx.org/bom","predicate":{"bomFormat":"CycloneDX","specVersion":"1.4","version":1,"metadata":{"timestamp":"2024-03-11T10:00:00Z","tools":[{"vendor":"Test Vendor","name":"Test Tool","version":"1.0.0"}]},"components":[]}}`,
		},
		{
			name:      "link",
			predType:  "link",
			predicate: `{"_type":"link","name":"test-link","command":["cmd"],"materials":{"hash":{"sha256":"123"}},"products":{"hash":{"sha256":"456"}},"byproducts":{"command":"test"},"environment":{"env":"test"}}`,
			wantJSON:  `{"_type":"https://in-toto.io/Statement/v0.1","subject":[{"name":"test-repo","digest":{"sha256":"abcdef123456"}}],"predicateType":"https://in-toto.io/Link/v1", "predicate":{"_type":"link","name":"test-link","command":["cmd"],"materials":{"hash":{"sha256":"123"}},"products":{"hash":{"sha256":"456"}},"byproducts":{"command":"test"},"environment":{"env":"test"}}}`,
		},
		{
			name:      "link minimal",
			predType:  "link",
			predicate: `{"_type":"link","name":"minimal-link","command":["do"],"materials":{},"products":{},"byproducts":{},"environment":{"env":"test"}}`,
			wantJSON:  `{"_type":"https://in-toto.io/Statement/v0.1","subject":[{"name":"test-repo","digest":{"sha256":"abcdef123456"}}],"predicateType":"https://in-toto.io/Link/v1", "predicate":{"_type":"link","name":"minimal-link","command":["do"],"materials":{},"products":{},"byproducts":{},"environment":{"env":"test"}}}`,
		},
		{
			name:      "vuln",
			predType:  "vuln",
			predicate: `{"invocation":{"parameters":"foo=bar","uri":"test-uri","event_id":"123","builder.id":"456"},"scanner":{"uri":"test-scanner","version":"2","db":{"uri":"test-db-uri","version":"3"},"result":"passed"},"metadata":{"scanStartedOn":"2024-03-11T10:00:00Z","scanFinishedOn":"2024-03-11T10:05:00Z"}}`,
			wantJSON:  `{"_type":"https://in-toto.io/Statement/v0.1","subject":[{"name":"test-repo","digest":{"sha256":"abcdef123456"}}],"predicateType":"https://cosign.sigstore.dev/attestation/vuln/v1","predicate":{"invocation":{"parameters":"foo=bar","uri":"test-uri","event_id":"123","builder.id":"456"},"scanner":{"uri":"test-scanner","version":"2","db":{"uri":"test-db-uri","version":"3"},"result":"passed"},"metadata":{"scanStartedOn":"2024-03-11T10:00:00Z","scanFinishedOn":"2024-03-11T10:05:00Z"}}}`,
		},
		{
			name:      "vuln minimal",
			predType:  "vuln",
			predicate: `{"invocation":{},"scanner":{"uri":"test-scanner"},"metadata":{"scanStartedOn":"2024-03-11T10:00:00Z"}}`,
			wantJSON:  `{"_type":"https://in-toto.io/Statement/v0.1","subject":[{"name":"test-repo","digest":{"sha256":"abcdef123456"}}],"predicateType":"https://cosign.sigstore.dev/attestation/vuln/v1","predicate":{"invocation":{"parameters":null,"uri":"","event_id":"","builder.id":""},"scanner":{"uri":"test-scanner","version":"","db":{"uri":"","version":""},"result":null},"metadata":{"scanStartedOn":"2024-03-11T10:00:00Z","scanFinishedOn":"0001-01-01T00:00:00Z"}}}`,
		},
		{
			name:      "openvex",
			predType:  "openvex",
			predicate: `{"@context":"https://openvex.dev/ns","@id":"some-id"}`,
			wantJSON:  `{"_type":"https://in-toto.io/Statement/v0.1","subject":[{"name":"test-repo","digest":{"sha256":"abcdef123456"}}],"predicateType":"https://openvex.dev/ns","predicate":{"@context":"https://openvex.dev/ns","@id":"some-id"}}`,
		},
		{
			name:     "openvex complex",
			predType: "openvex",
			predicate: `{
                                "@context": "https://openvex.dev/ns",
                                "@id": "https://example.com/vex/doc-1",
                                "author": "Test Author",
                                "timestamp": "2024-03-11T10:00:00Z",
                                "statements": [
                                        {
                                                "vulnerability": "CVE-2026-5678",
                                                "products": ["pkg:npm/test-package@1.0.0"],
                                                "status": "not_affected"
                                        }
                                ]
                        }`,
			wantJSON: `{"_type":"https://in-toto.io/Statement/v0.1","subject":[{"name":"test-repo","digest":{"sha256":"abcdef123456"}}],"predicateType":"https://openvex.dev/ns","predicate":{"@context":"https://openvex.dev/ns","@id":"https://example.com/vex/doc-1","author":"Test Author","timestamp":"2024-03-11T10:00:00Z","statements":[{"vulnerability":"CVE-2026-5678","products":["pkg:npm/test-package@1.0.0"],"status":"not_affected"}]}}`,
		},
		{
			name:      "openvex minimal",
			predType:  "openvex",
			predicate: `{"@context":"https://openvex.dev/ns","@id":"some-id"}`,
			wantJSON:  `{"_type":"https://in-toto.io/Statement/v0.1","subject":[{"name":"test-repo","digest":{"sha256":"abcdef123456"}}],"predicateType":"https://openvex.dev/ns","predicate":{"@context":"https://openvex.dev/ns","@id":"some-id"}}`,
		},
		{
			name:      "slsaprovenance",
			predType:  "slsaprovenance",
			predicate: `{"builder":{"id":"2"},"buildType":"test"}`,
			wantJSON:  `{"_type":"https://in-toto.io/Statement/v0.1","subject":[{"name":"test-repo","digest":{"sha256":"abcdef123456"}}],"predicateType":"https://slsa.dev/provenance/v0.2","predicate":{"builder":{"id":"2"},"buildType":"test","invocation":{"configSource":{}}}}`,
		},
		{
			name:      "slsaprovenance02",
			predType:  "slsaprovenance02",
			predicate: `{"builder":{"id":"2"},"buildType":"test"}`,
			wantJSON:  `{"_type":"https://in-toto.io/Statement/v0.1","subject":[{"name":"test-repo","digest":{"sha256":"abcdef123456"}}],"predicateType":"https://slsa.dev/provenance/v0.2","predicate":{"builder":{"id":"2"},"buildType":"test","invocation":{"configSource":{}}}}`,
		},
		{
			name:      "slsaprovenance1",
			predType:  "slsaprovenance1",
			predicate: `{"buildDefinition":{"buildType":"test"},"runDetails":{"builder":{"id":"x"}}}`,
			wantJSON:  `{"_type":"https://in-toto.io/Statement/v0.1","subject":[{"name":"test-repo","digest":{"sha256":"abcdef123456"}}],"predicateType":"https://slsa.dev/provenance/v1","predicate":{"buildDefinition":{"buildType":"test","externalParameters":null},"runDetails":{"builder":{"id":"x"},"metadata":{}}}}`,
		},
		{
			name:     "slsaprovenance1 complex",
			predType: "slsaprovenance1",
			predicate: `{
                                "buildDefinition": {
                                        "buildType": "https://example.com/Makefile",
                                        "externalParameters": {
                                                "version": "1.0"
                                        },
                                        "internalParameters": {},
                                        "resolvedDependencies": [
                                                {
                                                        "uri": "git+https://example.com/repo.git",
                                                        "digest": {"sha1": "abcdef123456"}
                                                }
                                        ]
                                },
                                "runDetails": {
                                        "builder": {
                                                "id": "https://example.com/builder"
                                        },
                                        "metadata": {
                                                "invocationID": "test-invocation"
                                        },
                                        "byproducts": []
                                }
                        }`,
			wantJSON: `{"_type":"https://in-toto.io/Statement/v0.1","subject":[{"name":"test-repo","digest":{"sha256":"abcdef123456"}}],"predicateType":"https://slsa.dev/provenance/v1","predicate":{"buildDefinition":{"buildType":"https://example.com/Makefile","externalParameters":{"version":"1.0"},"internalParameters":{},"resolvedDependencies":[{"uri":"git+https://example.com/repo.git","digest":{"sha1":"abcdef123456"}}]},"runDetails":{"builder":{"id":"https://example.com/builder"},"metadata":{"invocationID":"test-invocation"}}}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts.Type = tt.predType
			opts.Predicate = strings.NewReader(tt.predicate)

			gotStmt, err := GenerateStatement(opts)
			if err != nil {
				t.Fatalf("GenerateStatement() error = %v", err)
			}

			gotJSON, err := json.Marshal(gotStmt)
			if err != nil {
				t.Fatalf("gotStmt.MarshalJSON() error = %v", err)
			}

			if diff := cmp.Diff(normalizeJSON(t, []byte(tt.wantJSON)), normalizeJSON(t, gotJSON)); diff != "" {
				t.Errorf("GenerateStatement() JSON diff (-want +got): %s", diff)
				t.Logf("GOT JSON: %s", string(gotJSON))
			}
		})
	}
}

func normalizeJSON(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("json.Unmarshal error for: %s %v", string(data), err)
	}
	return v
}
