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
	"bytes"
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/go-openapi/strfmt"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/pkg/errors"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/pkg/cosign/bundle"
	ctuf "github.com/sigstore/cosign/pkg/cosign/tuf"
	"github.com/sigstore/cosign/pkg/oci/static"
	"github.com/sigstore/cosign/pkg/types"
	"github.com/sigstore/cosign/test"
	rtypes "github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
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

func appendSlices(slices [][]byte) []byte {
	var tmp []byte
	for _, s := range slices {
		tmp = append(tmp, s...)
	}
	return tmp
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

func TestVerifyImageSignature(t *testing.T) {
	rootCert, rootKey, _ := test.GenerateRootCa()
	subCert, subKey, _ := test.GenerateSubordinateCa(rootCert, rootKey)
	leafCert, privKey, _ := test.GenerateLeafCert("subject", "oidc-issuer", subCert, subKey)
	pemRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Raw})
	pemSub := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: subCert.Raw})
	pemLeaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Raw})

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	payload := []byte{1, 2, 3, 4}
	h := sha256.Sum256(payload)
	signature, _ := privKey.Sign(rand.Reader, h[:], crypto.SHA256)

	ociSig, _ := static.NewSignature(payload,
		base64.StdEncoding.EncodeToString(signature),
		static.WithCertChain(pemLeaf, appendSlices([][]byte{pemSub, pemRoot})))
	verified, err := VerifyImageSignature(context.TODO(), ociSig, v1.Hash{}, &CheckOpts{RootCerts: rootPool})
	if err != nil {
		t.Fatalf("unexpected error while verifying signature, expected no error, got %v", err)
	}
	// TODO: Create fake bundle and test verification
	if verified == true {
		t.Fatalf("expected verified=false, got verified=true")
	}
}

func TestVerifyImageSignatureMultipleSubs(t *testing.T) {
	rootCert, rootKey, _ := test.GenerateRootCa()
	subCert1, subKey1, _ := test.GenerateSubordinateCa(rootCert, rootKey)
	subCert2, subKey2, _ := test.GenerateSubordinateCa(subCert1, subKey1)
	subCert3, subKey3, _ := test.GenerateSubordinateCa(subCert2, subKey2)
	leafCert, privKey, _ := test.GenerateLeafCert("subject", "oidc-issuer", subCert3, subKey3)
	pemRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Raw})
	pemSub1 := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: subCert1.Raw})
	pemSub2 := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: subCert2.Raw})
	pemSub3 := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: subCert3.Raw})
	pemLeaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Raw})

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	payload := []byte{1, 2, 3, 4}
	h := sha256.Sum256(payload)
	signature, _ := privKey.Sign(rand.Reader, h[:], crypto.SHA256)

	ociSig, _ := static.NewSignature(payload,
		base64.StdEncoding.EncodeToString(signature), static.WithCertChain(pemLeaf, appendSlices([][]byte{pemSub3, pemSub2, pemSub1, pemRoot})))
	verified, err := VerifyImageSignature(context.TODO(), ociSig, v1.Hash{}, &CheckOpts{RootCerts: rootPool})
	if err != nil {
		t.Fatalf("unexpected error while verifying signature, expected no error, got %v", err)
	}
	// TODO: Create fake bundle and test verification
	if verified == true {
		t.Fatalf("expected verified=false, got verified=true")
	}
}

func signEntry(ctx context.Context, t *testing.T, signer signature.Signer, entry bundle.RekorPayload) []byte {
	payload, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshalling error: %v", err)
	}
	canonicalized, err := jsoncanonicalizer.Transform(payload)
	if err != nil {
		t.Fatalf("canonicalizing error: %v", err)
	}
	signature, err := signer.SignMessage(bytes.NewReader(canonicalized), options.WithContext(ctx))
	if err != nil {
		t.Fatalf("signing error: %v", err)
	}
	return signature
}

func CreateTestBundle(ctx context.Context, t *testing.T, root ctuf.TestSigstoreRoot, leaf []byte) *bundle.RekorBundle {
	// generate log ID according to rekor public key
	pk, _ := root.Rekor.PublicKey(nil)
	keyID, _ := getLogID(pk)
	pyld := bundle.RekorPayload{
		Body:           base64.StdEncoding.EncodeToString(leaf),
		IntegratedTime: time.Now().Unix(),
		LogIndex:       693591,
		LogID:          keyID,
	}
	// Sign with root.
	signature := signEntry(ctx, t, root.Rekor, pyld)
	b := &bundle.RekorBundle{
		SignedEntryTimestamp: strfmt.Base64(signature),
		Payload:              pyld,
	}
	return b
}

func TestVerifyImageSignatureWithNoChain(t *testing.T) {
	ctx := context.Background()
	rootCert, rootKey, _ := test.GenerateRootCa()
	sv, _, err := signature.NewECDSASignerVerifier(elliptic.P256(), rand.Reader, crypto.SHA256)
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}
	testSigstoreRoot := ctuf.TestSigstoreRoot{
		Rekor:             sv,
		FulcioCertificate: rootCert,
	}
	_, _ = ctuf.NewSigstoreTufRepo(t, testSigstoreRoot)

	leafCert, privKey, _ := test.GenerateLeafCert("subject", "oidc-issuer", rootCert, rootKey)
	pemLeaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Raw})

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	payload := []byte{1, 2, 3, 4}
	h := sha256.Sum256(payload)
	signature, _ := privKey.Sign(rand.Reader, h[:], crypto.SHA256)

	// Create a fake bundle
	pe, _ := proposedEntry(base64.StdEncoding.EncodeToString(signature), payload, pemLeaf)
	entry, _ := rtypes.NewEntry(pe[0])
	leaf, _ := entry.Canonicalize(ctx)
	rekorBundle := CreateTestBundle(ctx, t, testSigstoreRoot, leaf)

	opts := []static.Option{static.WithCertChain(pemLeaf, []byte{}), static.WithBundle(rekorBundle)}
	ociSig, _ := static.NewSignature(payload, base64.StdEncoding.EncodeToString(signature), opts...)

	verified, err := VerifyImageSignature(context.TODO(), ociSig, v1.Hash{}, &CheckOpts{RootCerts: rootPool})
	if err != nil {
		t.Fatalf("unexpected error while verifying signature, expected no error, got %v", err)
	}
	if verified == false {
		t.Fatalf("expected verified=true, got verified=false")
	}
}

func TestVerifyImageSignatureWithOnlyRoot(t *testing.T) {
	rootCert, rootKey, _ := test.GenerateRootCa()
	leafCert, privKey, _ := test.GenerateLeafCert("subject", "oidc-issuer", rootCert, rootKey)
	pemRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Raw})
	pemLeaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Raw})

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	payload := []byte{1, 2, 3, 4}
	h := sha256.Sum256(payload)
	signature, _ := privKey.Sign(rand.Reader, h[:], crypto.SHA256)

	ociSig, _ := static.NewSignature(payload, base64.StdEncoding.EncodeToString(signature), static.WithCertChain(pemLeaf, pemRoot))
	verified, err := VerifyImageSignature(context.TODO(), ociSig, v1.Hash{}, &CheckOpts{RootCerts: rootPool})
	if err != nil {
		t.Fatalf("unexpected error while verifying signature, expected no error, got %v", err)
	}
	// TODO: Create fake bundle and test verification
	if verified == true {
		t.Fatalf("expected verified=false, got verified=true")
	}
}

func TestVerifyImageSignatureWithMissingSub(t *testing.T) {
	rootCert, rootKey, _ := test.GenerateRootCa()
	subCert, subKey, _ := test.GenerateSubordinateCa(rootCert, rootKey)
	leafCert, privKey, _ := test.GenerateLeafCert("subject", "oidc-issuer", subCert, subKey)
	pemRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Raw})
	pemLeaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Raw})

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	payload := []byte{1, 2, 3, 4}
	h := sha256.Sum256(payload)
	signature, _ := privKey.Sign(rand.Reader, h[:], crypto.SHA256)

	ociSig, _ := static.NewSignature(payload, base64.StdEncoding.EncodeToString(signature), static.WithCertChain(pemLeaf, pemRoot))
	verified, err := VerifyImageSignature(context.TODO(), ociSig, v1.Hash{}, &CheckOpts{RootCerts: rootPool})
	if err == nil {
		t.Fatal("expected error while verifying signature")
	}
	if !strings.Contains(err.Error(), "certificate signed by unknown authority") {
		t.Fatal("expected error while verifying signature")
	}
	// TODO: Create fake bundle and test verification
	if verified == true {
		t.Fatalf("expected verified=false, got verified=true")
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

func TestValidateAndUnpackCertWithChainSuccess(t *testing.T) {
	subject := "email@email"
	oidcIssuer := "https://accounts.google.com"

	rootCert, rootKey, _ := test.GenerateRootCa()
	subCert, subKey, _ := test.GenerateSubordinateCa(rootCert, rootKey)
	leafCert, _, _ := test.GenerateLeafCert(subject, oidcIssuer, subCert, subKey)

	co := &CheckOpts{
		CertEmail:      subject,
		CertOidcIssuer: oidcIssuer,
	}

	_, err := ValidateAndUnpackCertWithChain(leafCert, []*x509.Certificate{subCert, leafCert}, co)
	if err != nil {
		t.Errorf("ValidateAndUnpackCert expected no error, got err = %v", err)
	}
}

func TestValidateAndUnpackCertWithChainSuccessWithRoot(t *testing.T) {
	subject := "email@email"
	oidcIssuer := "https://accounts.google.com"

	rootCert, rootKey, _ := test.GenerateRootCa()
	leafCert, _, _ := test.GenerateLeafCert(subject, oidcIssuer, rootCert, rootKey)

	co := &CheckOpts{
		CertEmail:      subject,
		CertOidcIssuer: oidcIssuer,
	}

	_, err := ValidateAndUnpackCertWithChain(leafCert, []*x509.Certificate{rootCert}, co)
	if err != nil {
		t.Errorf("ValidateAndUnpackCert expected no error, got err = %v", err)
	}
}

func TestValidateAndUnpackCertWithChainFailsWithoutChain(t *testing.T) {
	subject := "email@email"
	oidcIssuer := "https://accounts.google.com"

	rootCert, rootKey, _ := test.GenerateRootCa()
	leafCert, _, _ := test.GenerateLeafCert(subject, oidcIssuer, rootCert, rootKey)

	co := &CheckOpts{
		CertEmail:      subject,
		CertOidcIssuer: oidcIssuer,
	}

	_, err := ValidateAndUnpackCertWithChain(leafCert, []*x509.Certificate{}, co)
	if err == nil || err.Error() != "no chain provided to validate certificate" {
		t.Errorf("expected error without chain, got %v", err)
	}
}

func TestValidateAndUnpackCertWithChainFailsWithInvalidChain(t *testing.T) {
	subject := "email@email"
	oidcIssuer := "https://accounts.google.com"

	rootCert, rootKey, _ := test.GenerateRootCa()
	leafCert, _, _ := test.GenerateLeafCert(subject, oidcIssuer, rootCert, rootKey)
	rootCertOther, _, _ := test.GenerateRootCa()

	co := &CheckOpts{
		CertEmail:      subject,
		CertOidcIssuer: oidcIssuer,
	}

	_, err := ValidateAndUnpackCertWithChain(leafCert, []*x509.Certificate{rootCertOther}, co)
	if err == nil || !strings.Contains(err.Error(), "certificate signed by unknown authority") {
		t.Errorf("expected error without valid chain, got %v", err)
	}
}

func TestCompareSigs(t *testing.T) {
	// TODO(nsmith5): Add test cases for invalid signature, missing signature etc
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

func TestTrustedCertSuccess(t *testing.T) {
	rootCert, rootKey, _ := test.GenerateRootCa()
	subCert, subKey, _ := test.GenerateSubordinateCa(rootCert, rootKey)
	leafCert, _, _ := test.GenerateLeafCert("subject", "oidc-issuer", subCert, subKey)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)
	subPool := x509.NewCertPool()
	subPool.AddCert(subCert)

	err := TrustedCert(leafCert, rootPool, subPool)
	if err != nil {
		t.Fatalf("expected no error verifying certificate, got %v", err)
	}
}

func TestTrustedCertSuccessNoIntermediates(t *testing.T) {
	rootCert, rootKey, _ := test.GenerateRootCa()
	leafCert, _, _ := test.GenerateLeafCert("subject", "oidc-issuer", rootCert, rootKey)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	err := TrustedCert(leafCert, rootPool, nil)
	if err != nil {
		t.Fatalf("expected no error verifying certificate, got %v", err)
	}
}

// Tests that verification succeeds if both a root and subordinate pool are
// present, but a chain is built with only the leaf and root certificates.
func TestTrustedCertSuccessChainFromRoot(t *testing.T) {
	rootCert, rootKey, _ := test.GenerateRootCa()
	leafCert, _, _ := test.GenerateLeafCert("subject", "oidc-issuer", rootCert, rootKey)
	subCert, _, _ := test.GenerateSubordinateCa(rootCert, rootKey)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)
	subPool := x509.NewCertPool()
	subPool.AddCert(subCert)

	err := TrustedCert(leafCert, rootPool, subPool)
	if err != nil {
		t.Fatalf("expected no error verifying certificate, got %v", err)
	}
}
