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
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"testing"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/pkg/errors"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/pkg/oci/static"
	"github.com/sigstore/cosign/pkg/types"
	"github.com/sigstore/cosign/test"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/require"
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

func TestValidateAndUnpackCertSuccess(t *testing.T) {
	subject := "email@email"
	oidcIssuer := "https://accounts.google.com"

	rootCert, rootKey, _ := test.GenerateRootCa()
	leafCert, _, _ := test.GenerateLeafCert(subject, oidcIssuer, rootCert, rootKey)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	co := &CheckOpts{
		RootCerts:      rootPool,
		CertEmail:      subject,
		CertOidcIssuer: oidcIssuer,
	}

	_, err := ValidateAndUnpackCert(leafCert, co)
	if err != nil {
		t.Errorf("ValidateAndUnpackCert expected no error, got err = %v", err)
	}
}

func TestValidateAndUnpackCertSuccessAllowAllValues(t *testing.T) {
	subject := "email@email"
	oidcIssuer := "https://accounts.google.com"

	rootCert, rootKey, _ := test.GenerateRootCa()
	leafCert, _, _ := test.GenerateLeafCert(subject, oidcIssuer, rootCert, rootKey)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	co := &CheckOpts{
		RootCerts: rootPool,
	}

	_, err := ValidateAndUnpackCert(leafCert, co)
	if err != nil {
		t.Errorf("ValidateAndUnpackCert expected no error, got err = %v", err)
	}
}

func TestValidateAndUnpackCertInvalidRoot(t *testing.T) {
	subject := "email@email"
	oidcIssuer := "https://accounts.google.com"

	rootCert, rootKey, _ := test.GenerateRootCa()
	leafCert, _, _ := test.GenerateLeafCert(subject, oidcIssuer, rootCert, rootKey)

	otherRoot, _, _ := test.GenerateRootCa()

	rootPool := x509.NewCertPool()
	rootPool.AddCert(otherRoot)

	co := &CheckOpts{
		RootCerts:      rootPool,
		CertEmail:      subject,
		CertOidcIssuer: oidcIssuer,
	}

	_, err := ValidateAndUnpackCert(leafCert, co)
	require.Contains(t, err.Error(), "certificate signed by unknown authority")
}

func TestValidateAndUnpackCertInvalidOidcIssuer(t *testing.T) {
	subject := "email@email"
	oidcIssuer := "https://accounts.google.com"

	rootCert, rootKey, _ := test.GenerateRootCa()
	leafCert, _, _ := test.GenerateLeafCert(subject, oidcIssuer, rootCert, rootKey)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	co := &CheckOpts{
		RootCerts:      rootPool,
		CertEmail:      subject,
		CertOidcIssuer: "other",
	}

	_, err := ValidateAndUnpackCert(leafCert, co)
	require.Contains(t, err.Error(), "expected oidc issuer not found in certificate")
}

func TestValidateAndUnpackCertInvalidEmail(t *testing.T) {
	subject := "email@email"
	oidcIssuer := "https://accounts.google.com"

	rootCert, rootKey, _ := test.GenerateRootCa()
	leafCert, _, _ := test.GenerateLeafCert(subject, oidcIssuer, rootCert, rootKey)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	co := &CheckOpts{
		RootCerts:      rootPool,
		CertEmail:      "other",
		CertOidcIssuer: oidcIssuer,
	}

	_, err := ValidateAndUnpackCert(leafCert, co)
	require.Contains(t, err.Error(), "expected email not found in certificate")
}

func TestCompareSigs(t *testing.T) {
	//TODO(nsmith5): Add test cases for invalid signature, missing signature etc
	tests := []struct {
		description string
		b64sig      string
		bundleBody  string
		shouldErr   bool
	}{
		{
			description: "sigs match",
			b64sig:      "MEQCIDO3XHbLovPWK+bk8ItCig2cwlr/8MXbLvz3UFzxMGIMAiA1lqdM9IqqUvCUqzOjufTq3sKU3qSn7R5tPqPz0ddNwQ==",
			bundleBody:  `eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiIzODE1MmQxZGQzMjZhZjQwNWY4OTlkYmNjMmNlMzUwYjVmMTZkNDVkZjdmMjNjNDg4ZjQ4NTBhZmExY2Q4NmQxIn19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FUUNJRE8zWEhiTG92UFdLK2JrOEl0Q2lnMmN3bHIvOE1YYkx2ejNVRnp4TUdJTUFpQTFscWRNOUlxcVV2Q1Vxek9qdWZUcTNzS1UzcVNuN1I1dFBxUHowZGROd1E9PSIsInB1YmxpY0tleSI6eyJjb250ZW50IjoiTFMwdExTMUNSVWRKVGlCUVZVSk1TVU1nUzBWWkxTMHRMUzBLVFVacmQwVjNXVWhMYjFwSmVtb3dRMEZSV1VsTGIxcEplbW93UkVGUlkwUlJaMEZGVUN0RVIyb3ZXWFV4VG5vd01XVjVSV2hVZDNRMlQya3hXV3BGWXdwSloxRldjRlZTTjB0bUwwSm1hVk16Y1ZReFVHd3dkbGh3ZUZwNVMyWkpSMHMyZWxoQ04ybE5aV3RFVTA1M1dHWldPSEpKYUdaMmRrOW5QVDBLTFMwdExTMUZUa1FnVUZWQ1RFbERJRXRGV1MwdExTMHRDZz09In19fX0=`,
		},
		{
			description: "sigs don't match",
			b64sig:      "bm9wZQo=",
			bundleBody:  `eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiIzODE1MmQxZGQzMjZhZjQwNWY4OTlkYmNjMmNlMzUwYjVmMTZkNDVkZjdmMjNjNDg4ZjQ4NTBhZmExY2Q4NmQxIn19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FUUNJRE8zWEhiTG92UFdLK2JrOEl0Q2lnMmN3bHIvOE1YYkx2ejNVRnp4TUdJTUFpQTFscWRNOUlxcVV2Q1Vxek9qdWZUcTNzS1UzcVNuN1I1dFBxUHowZGROd1E9PSIsInB1YmxpY0tleSI6eyJjb250ZW50IjoiTFMwdExTMUNSVWRKVGlCUVZVSk1TVU1nUzBWWkxTMHRMUzBLVFVacmQwVjNXVWhMYjFwSmVtb3dRMEZSV1VsTGIxcEplbW93UkVGUlkwUlJaMEZGVUN0RVIyb3ZXWFV4VG5vd01XVjVSV2hVZDNRMlQya3hXV3BGWXdwSloxRldjRlZTTjB0bUwwSm1hVk16Y1ZReFVHd3dkbGh3ZUZwNVMyWkpSMHMyZWxoQ04ybE5aV3RFVTA1M1dHWldPSEpKYUdaMmRrOW5QVDBLTFMwdExTMUZUa1FnVUZWQ1RFbERJRXRGV1MwdExTMHRDZz09In19fX0=`,
			shouldErr:   true,
		},
	}
	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			sig, err := static.NewSignature([]byte("payload"), test.b64sig)
			if err != nil {
				t.Fatalf("failed to create static signature: %v", err)
			}
			err = compareSigs(test.bundleBody, sig)
			if err == nil && test.shouldErr {
				t.Fatal("test should have errored")
			}
			if err != nil && !test.shouldErr {
				t.Fatal(err)
			}
		})
	}
}
