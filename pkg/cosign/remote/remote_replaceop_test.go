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
	}{
		{name: "null payload", payloadDoc: `{"payload":null}`},
		{name: "object payload", payloadDoc: `{"payload":{}}`},
		{name: "number payload", payloadDoc: `{"payload":123}`},
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
			if !strings.Contains(err.Error(), "'payload' field is not a string") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
