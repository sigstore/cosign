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

package remote

import (
	"strings"
	"testing"

	"github.com/sigstore/cosign/v3/pkg/oci"
	ociempty "github.com/sigstore/cosign/v3/pkg/oci/empty"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
)

type mockOCISignatures struct {
	oci.Signatures
	signatures []oci.Signature
}

func (m *mockOCISignatures) Get() ([]oci.Signature, error) {
	return m.signatures, nil
}

func TestReplaceOpRejectsNonStringPayloadWithoutPanic(t *testing.T) {
	tests := []struct {
		name       string
		payloadDoc string
		wantSubstr string
	}{
		{name: "missing payload", payloadDoc: `{}`, wantSubstr: "could not find 'payload'"},
		{name: "null payload", payloadDoc: `{"payload":null}`, wantSubstr: "'payload' field is not a string"},
		{name: "object payload", payloadDoc: `{"payload":{}}`, wantSubstr: "'payload' field is not a string"},
		{name: "number payload", payloadDoc: `{"payload":123}`, wantSubstr: "'payload' field is not a string"},
		{name: "invalid base64 payload", payloadDoc: `{"payload":"%%%"}`, wantSubstr: "could not decode 'payload'"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("unexpected panic: %v", r)
				}
			}()

			existing, err := static.NewSignature([]byte(tt.payloadDoc), "")
			if err != nil {
				t.Fatalf("static.NewSignature() = %v", err)
			}
			newSig, err := static.NewSignature([]byte(`{"payload":"AA=="}`), "")
			if err != nil {
				t.Fatalf("static.NewSignature() = %v", err)
			}

			sigs := &mockOCISignatures{
				Signatures: ociempty.Signatures(), // satisfies the v1.Image surface
				signatures: []oci.Signature{existing},
			}

			replaceOp := NewReplaceOp("https://example.com/predicateType")
			_, err = replaceOp.Replace(sigs, newSig)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantSubstr) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
