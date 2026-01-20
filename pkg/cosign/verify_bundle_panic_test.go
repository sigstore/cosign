package cosign

import (
	"crypto/x509"
	"fmt"
	"io"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v3/pkg/oci"
)

type bundleSignatureStub struct {
	bundle *bundle.RekorBundle
}

func (bss *bundleSignatureStub) Annotations() (map[string]string, error) {
	return map[string]string{}, nil
}
func (bss *bundleSignatureStub) Payload() ([]byte, error)         { return []byte{}, nil }
func (bss *bundleSignatureStub) Signature() ([]byte, error)       { return []byte{}, nil }
func (bss *bundleSignatureStub) Base64Signature() (string, error) { return "", nil }
func (bss *bundleSignatureStub) Cert() (*x509.Certificate, error) {
	return nil, fmt.Errorf("unimplemented")
}
func (bss *bundleSignatureStub) Chain() ([]*x509.Certificate, error) {
	return nil, fmt.Errorf("unimplemented")
}
func (bss *bundleSignatureStub) Bundle() (*bundle.RekorBundle, error) { return bss.bundle, nil }
func (bss *bundleSignatureStub) RFC3161Timestamp() (*bundle.RFC3161Timestamp, error) {
	return nil, fmt.Errorf("unimplemented")
}
func (bss *bundleSignatureStub) Digest() (v1.Hash, error) {
	return v1.Hash{}, fmt.Errorf("unimplemented")
}
func (bss *bundleSignatureStub) DiffID() (v1.Hash, error) {
	return v1.Hash{}, fmt.Errorf("unimplemented")
}
func (bss *bundleSignatureStub) Compressed() (io.ReadCloser, error) {
	return nil, fmt.Errorf("unimplemented")
}
func (bss *bundleSignatureStub) Uncompressed() (io.ReadCloser, error) {
	return nil, fmt.Errorf("unimplemented")
}
func (bss *bundleSignatureStub) Size() (int64, error) { return 0, fmt.Errorf("unimplemented") }
func (bss *bundleSignatureStub) MediaType() (types.MediaType, error) {
	return types.DockerConfigJSON, fmt.Errorf("unimplemented")
}

var _ oci.Signature = (*bundleSignatureStub)(nil)

func TestVerifyBundleRejectsMalformedBundleBodyWithoutPanic(t *testing.T) {
	rekorPubKeys := NewTrustedTransparencyLogPubKeys()
	co := &CheckOpts{RekorPubKeys: &rekorPubKeys}

	tests := []struct {
		name string
		body interface{}
	}{
		{name: "nil body", body: nil},
		{name: "object body", body: map[string]interface{}{"k": "v"}},
		{name: "number body", body: float64(123)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("unexpected panic: %v", r)
				}
			}()

			sig := &bundleSignatureStub{
				bundle: &bundle.RekorBundle{
					Payload: bundle.RekorPayload{
						Body:           tt.body,
						IntegratedTime: 0,
						LogIndex:       0,
						LogID:          "",
					},
				},
			}

			if _, err := VerifyBundle(sig, co); err == nil {
				t.Fatalf("expected error, got nil")
			}
		})
	}
}
