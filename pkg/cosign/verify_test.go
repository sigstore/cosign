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

package cosign

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"io"
	"testing"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/pkg/errors"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/pkg/types"
	"github.com/sigstore/sigstore/pkg/signature"
)

type mockVerifier struct {
	shouldErr bool
}

func (m *mockVerifier) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return nil, nil
}

func (m *mockVerifier) VerifySignature(signature, message io.Reader, opts ...signature.VerifyOption) error {
	if m.shouldErr {
		return errors.New("failure")
	}
	return nil
}

var _ signature.Verifier = (*mockVerifier)(nil)

type mockAttestation struct {
	payload interface{}
}

var _ payloader = (*mockAttestation)(nil)

func (m *mockAttestation) Annotations() (map[string]string, error) {
	return nil, nil
}

func (m *mockAttestation) Payload() ([]byte, error) {
	return json.Marshal(m.payload)
}
func Test_verifyOCIAttestation(t *testing.T) {
	stmt, err := json.Marshal(in_toto.ProvenanceStatement{})
	if err != nil {
		t.Fatal(err)
	}
	valid := map[string]interface{}{
		"payloadType": types.IntotoPayloadType,
		"payload":     stmt,
		"signatures":  []dsse.Signature{{Sig: base64.StdEncoding.EncodeToString([]byte("foobar"))}},
	}
	// Should Verify
	if err := verifyOCIAttestation(context.TODO(), &mockVerifier{}, &mockAttestation{payload: valid}); err != nil {
		t.Errorf("verifyOCIAttestation() error = %v", err)
	}

	invalid := map[string]interface{}{
		"payloadType": "not valid type",
		"payload":     stmt,
		"signatures":  []dsse.Signature{{Sig: base64.StdEncoding.EncodeToString([]byte("foobar"))}},
	}

	// Should Not Verify
	if err := verifyOCIAttestation(context.TODO(), &mockVerifier{}, &mockAttestation{payload: invalid}); err == nil {
		t.Error("verifyOCIAttestation() expected invalid payload type error, got nil")
	}

	if err := verifyOCIAttestation(context.TODO(), &mockVerifier{shouldErr: true}, &mockAttestation{payload: valid}); err == nil {
		t.Error("verifyOCIAttestation() expected invalid payload type error, got nil")
	}
}
