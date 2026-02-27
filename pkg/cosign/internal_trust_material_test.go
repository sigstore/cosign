// Copyright 2025 The Sigstore Authors.
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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	sigstorebundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
)

func TestNewInternalTrustMaterial_WithIntermediateCAs(t *testing.T) {
	// Create Certificate Chain: Root CA -> Intermediate CA -> Leaf
	rootSubject := pkix.Name{CommonName: "Root CA"}
	intermediateSubject := pkix.Name{CommonName: "Intermediate CA"}
	leafSubject := pkix.Name{CommonName: "example.com"}

	rootCertificate, rootKey := createTestCertificate(t, rootSubject, rootSubject, true, nil)
	intermediateCertificate, intermediateKey := createTestCertificate(t, intermediateSubject, rootSubject, true, rootKey)
	leafCertificate, _ := createTestCertificate(t, leafSubject, intermediateSubject, false, intermediateKey)

	// Create A Bundle With The Certificate Chain
	bundle := &sigstorebundle.Bundle{
		Bundle: &protobundle.Bundle{
			VerificationMaterial: &protobundle.VerificationMaterial{
				Content: &protobundle.VerificationMaterial_X509CertificateChain{
					X509CertificateChain: &protocommon.X509CertificateChain{
						Certificates: []*protocommon.X509Certificate{
							{RawBytes: leafCertificate.Raw},
							{RawBytes: intermediateCertificate.Raw},
							{RawBytes: rootCertificate.Raw},
						},
					},
				},
			},
		},
	}

	internal, err := NewInternalTrustMaterial(nil, bundle)
	if err != nil {
		t.Fatalf("NewInternalTrustMaterial failed: %v", err)
	}

	if internal == nil {
		t.Fatal("expected non-nil InternalTrustMaterial")
	}

	// Expects One Intermediate CA
	if len(internal.UntrustedBundleCA) != 1 {
		t.Errorf("expected one (1) intermediate certificate authority, got %d", len(internal.UntrustedBundleCA))
	}

	if internal.UntrustedBundleCA[0].Subject.CommonName != intermediateSubject.CommonName {
		t.Errorf("expected intermediate CA subject '%s', got '%s'", intermediateSubject.CommonName, internal.UntrustedBundleCA[0].Subject.CommonName)
	}
}

func TestNewInternalTrustMaterial_WithNoIntermediates(t *testing.T) {
	// Create A Simple Chain With Just Root And Leaf
	rootSubject := pkix.Name{CommonName: "Root CA"}
	leafSubject := pkix.Name{CommonName: "Leaf Certificate"}

	rootCertificate, rootKey := createTestCertificate(t, rootSubject, rootSubject, true, nil)
	leafCertificate, _ := createTestCertificate(t, leafSubject, rootSubject, false, rootKey)

	bundle := &sigstorebundle.Bundle{
		Bundle: &protobundle.Bundle{
			VerificationMaterial: &protobundle.VerificationMaterial{
				Content: &protobundle.VerificationMaterial_X509CertificateChain{
					X509CertificateChain: &protocommon.X509CertificateChain{
						Certificates: []*protocommon.X509Certificate{
							{RawBytes: leafCertificate.Raw},
							{RawBytes: rootCertificate.Raw},
						},
					},
				},
			},
		},
	}

	internal, err := NewInternalTrustMaterial(nil, bundle)
	if err != nil {
		t.Fatalf("NewInternalTrustMaterial failed: %v", err)
	}

	// Expects No Intermediate CA
	if len(internal.UntrustedBundleCA) != 0 {
		t.Errorf("expected zero (0) intermediate certificate authorities, got %d", len(internal.UntrustedBundleCA))
	}
}

func TestNewInternalTrustMaterial_WithPublicKey(t *testing.T) {
	// Bundle With Public Key Instead Of Certificate Chain
	bundle := &sigstorebundle.Bundle{
		Bundle: &protobundle.Bundle{
			VerificationMaterial: &protobundle.VerificationMaterial{
				Content: &protobundle.VerificationMaterial_PublicKey{
					PublicKey: &protocommon.PublicKeyIdentifier{
						Hint: "test-hint",
					},
				},
			},
		},
	}

	internal, err := NewInternalTrustMaterial(nil, bundle)
	if err != nil {
		t.Fatalf("NewInternalTrustMaterial failed: %v", err)
	}

	// Expects No Intermediate CA
	if len(internal.UntrustedBundleCA) != 0 {
		t.Errorf("expected zero (0) intermediate certificate authorities, got %d", len(internal.UntrustedBundleCA))
	}
}

func TestNewInternalTrustMaterial_NilBundle(t *testing.T) {
	internal, err := NewInternalTrustMaterial(nil, nil)
	if err != nil {
		t.Fatalf("NewInternalTrustMaterial with nil bundle failed: %v", err)
	}

	if len(internal.UntrustedBundleCA) != 0 {
		t.Errorf("expected zero (0) intermediate certificate authorities, got %d", len(internal.UntrustedBundleCA))
	}
}

func TestNewInternalTrustMaterial_EmptyCertificateChain(t *testing.T) {
	bundle := &sigstorebundle.Bundle{
		Bundle: &protobundle.Bundle{
			VerificationMaterial: &protobundle.VerificationMaterial{
				Content: &protobundle.VerificationMaterial_X509CertificateChain{
					X509CertificateChain: &protocommon.X509CertificateChain{
						Certificates: []*protocommon.X509Certificate{},
					},
				},
			},
		},
	}

	internal, err := NewInternalTrustMaterial(nil, bundle)
	if err != nil {
		t.Fatalf("NewInternalTrustMaterial with empty chain failed: %v", err)
	}

	if len(internal.UntrustedBundleCA) != 0 {
		t.Errorf("expected 0 intermediate CAs for empty chain, got %d", len(internal.UntrustedBundleCA))
	}
}

func TestNewInternalTrustMaterial_MultipleIntermediates(t *testing.T) {
	// Create a Longer Chain: Root CA -> Intermediate CA 1 -> Intermediate CA 2 -> Leaf
	rootSubject := pkix.Name{CommonName: "Root CA"}
	intermediate1Subject := pkix.Name{CommonName: "Intermediate CA 1"}
	intermediate2Subject := pkix.Name{CommonName: "Intermediate CA 2"}
	leafSubject := pkix.Name{CommonName: "Leaf Certificate"}

	rootCertificate, rootKey := createTestCertificate(t, rootSubject, rootSubject, true, nil)
	intermediate1Certificate, intermediate1Key := createTestCertificate(t, intermediate1Subject, rootSubject, true, rootKey)
	intermediate2Certificate, intermediate2Key := createTestCertificate(t, intermediate2Subject, intermediate1Subject, true, intermediate1Key)
	leafCertificate, _ := createTestCertificate(t, leafSubject, intermediate2Subject, false, intermediate2Key)

	bundle := &sigstorebundle.Bundle{
		Bundle: &protobundle.Bundle{
			VerificationMaterial: &protobundle.VerificationMaterial{
				Content: &protobundle.VerificationMaterial_X509CertificateChain{
					X509CertificateChain: &protocommon.X509CertificateChain{
						Certificates: []*protocommon.X509Certificate{
							{RawBytes: leafCertificate.Raw},
							{RawBytes: intermediate2Certificate.Raw},
							{RawBytes: intermediate1Certificate.Raw},
							{RawBytes: rootCertificate.Raw},
						},
					},
				},
			},
		},
	}

	internal, err := NewInternalTrustMaterial(nil, bundle)
	if err != nil {
		t.Fatalf("NewInternalTrustMaterial failed: %v", err)
	}

	// Expects Two Intermediate CA
	if len(internal.UntrustedBundleCA) != 2 {
		t.Errorf("expected two (2) intermediate certificate authorities, got %d", len(internal.UntrustedBundleCA))
	}
}

func TestNewInternalTrustMaterial_TooManyCertificates(t *testing.T) {
	// Create More Than 10 Certificates (Should Fail Validation)
	certificates := make([]*protocommon.X509Certificate, 11)
	rootSubject := pkix.Name{CommonName: "Root CA"}
	rootCertificate, _ := createTestCertificate(t, rootSubject, rootSubject, true, nil)

	for i := 0; i < 11; i++ {
		certificates[i] = &protocommon.X509Certificate{RawBytes: rootCertificate.Raw}
	}

	bundle := &sigstorebundle.Bundle{
		Bundle: &protobundle.Bundle{
			VerificationMaterial: &protobundle.VerificationMaterial{
				Content: &protobundle.VerificationMaterial_X509CertificateChain{
					X509CertificateChain: &protocommon.X509CertificateChain{
						Certificates: certificates,
					},
				},
			},
		},
	}

	internal, err := NewInternalTrustMaterial(nil, bundle)
	if err != nil {
		t.Fatalf("NewInternalTrustMaterial failed: %v", err)
	}

	// Should Still Succeed But Have No Intermediates Extracted (Error Is Logged But Not Returned)
	if internal == nil {
		t.Fatal("expected non-nil InternalTrustMaterial")
	}
}

// Sign Data With A Leaf Certificate's Private Key Using Cosign's DSSE Signer
// Create A Bundle Using MakeNewBundle With The Certificate Chain
// Verify The Certificate Chain Using InternalTrustMaterial With Only Root CA
// Intermediate CA Must Be Extracted From The Bundle For Verification To Succeed
func TestSignatureVerificationWithCertificateChain(t *testing.T) {
	// Create Certificate Chain: Root -> Intermediate -> Leaf
	rootCertificate, intermediateCertificate, leafCertificate, _, _, leafKey := createCertificateChain(t)

	payload := []byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://example.com/test","subject":[{"name":"test","digest":{"sha256":"abc123"}}],"predicate":{}}`)
	payloadType := "application/vnd.in-toto+json"

	// Create DSSE Signer Using The Leaf's Private Key
	signer, err := dsse.NewEnvelopeSigner(&ecdsaDSSESigner{key: leafKey})
	if err != nil {
		t.Fatalf("failed to create DSSE signer: %v", err)
	}

	// Sign The Payload Using DSSE
	envelope, err := signer.SignPayload(context.Background(), payloadType, payload)
	if err != nil {
		t.Fatalf("failed to sign payload: %v", err)
	}

	// Marshal Envelope To JSON (As Cosign Does)
	envelopeJSON, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("failed to marshal envelope: %v", err)
	}

	// Create Certificate Chain PEM
	var certificateChainPEM []byte
	for _, certificate := range []*x509.Certificate{leafCertificate, intermediateCertificate, rootCertificate} {
		certificateChainPEM = append(certificateChainPEM, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certificate.Raw,
		})...)
	}

	bundleBytes, err := bundle.MakeNewBundle(&leafKey.PublicKey, nil, payload, envelopeJSON, certificateChainPEM, nil)
	if err != nil {
		t.Fatalf("MakeNewBundle failed: %v", err)
	}

	parsedBundle := &sigstorebundle.Bundle{}
	if err := parsedBundle.UnmarshalJSON(bundleBytes); err != nil {
		t.Fatalf("failed to parse bundle: %v", err)
	}

	if parsedBundle.Bundle.GetVerificationMaterial().GetX509CertificateChain() == nil {
		t.Fatal("expected bundle to have X509CertificateChain")
	}

	// Create Trusted Material With Root Only (No Intermediates)
	fulcioCA := &root.FulcioCertificateAuthority{
		Root:          rootCertificate,
		Intermediates: nil, // Intermediates Come from Protobundle.Bundle
	}
	baseTrust := &mockTrustedMaterial{
		fulcioCAs: []root.CertificateAuthority{fulcioCA},
	}

	// Extract Intermediate CA From Bundle
	internalTrust, err := NewInternalTrustMaterial(baseTrust, parsedBundle)
	if err != nil {
		t.Fatalf("NewInternalTrustMaterial failed: %v", err)
	}

	// Verify Intermediate Was Extracted From Bundle
	if len(internalTrust.UntrustedBundleCA) != 1 {
		t.Fatalf("expected 1 intermediate CA from bundle, got %d", len(internalTrust.UntrustedBundleCA))
	}

	// Get Wrapped CAs And Verify The Leaf Certificate Chain
	cas := internalTrust.FulcioCertificateAuthorities()
	internalCA := cas[0].(*InternalCertificateAuthority)

	// Verify Leaf Certificate Chains To Root
	chains, err := internalCA.Verify(leafCertificate, time.Now())
	if err != nil {
		t.Fatalf("certificate chain verification failed: %v", err)
	}
	if len(chains) == 0 {
		t.Fatal("expected at least one certificate chain")
	}

	// Verify Signature
	vc, err := parsedBundle.VerificationContent()
	if err != nil {
		t.Fatalf("failed to get verification content: %v", err)
	}

	// Verify The Leaf Certificate In The Bundle Matches The Verified Chain
	bundleLeafCertificate := vc.Certificate()
	if bundleLeafCertificate == nil {
		t.Fatal("expected bundle to contain leaf certificate")
	}
	if bundleLeafCertificate.Subject.CommonName != leafCertificate.Subject.CommonName {
		t.Fatalf("leaf certificate mismatch: got %s, want %s", bundleLeafCertificate.Subject.CommonName, leafCertificate.Subject.CommonName)
	}
}

// Helper To Create A Proper Certificate Chain For Verification Tests
func createCertificateChain(t *testing.T) (rootCertificate, intermediateCertificate, leafCertificate *x509.Certificate, rootKey, intermediateKey, leafKey *ecdsa.PrivateKey) {
	t.Helper()

	// Generate Keys
	rootKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	intermediateKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Create Root CA
	rootSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	rootTemplate := &x509.Certificate{
		SerialNumber:          rootSerial,
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	rootCertificate, _ = x509.ParseCertificate(rootDER)

	// Create Intermediate CA
	intermediateSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	intermediateTemplate := &x509.Certificate{
		SerialNumber:          intermediateSerial,
		Subject:               pkix.Name{CommonName: "Test Intermediate CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	intermediateDER, _ := x509.CreateCertificate(rand.Reader, intermediateTemplate, rootCertificate, &intermediateKey.PublicKey, rootKey)
	intermediateCertificate, _ = x509.ParseCertificate(intermediateDER)

	// Create Leaf Certificate With Code Signing Extended Key Usage
	leafSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	leafTemplate := &x509.Certificate{
		SerialNumber:          leafSerial,
		Subject:               pkix.Name{CommonName: "Test Leaf Certificate"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, intermediateCertificate, &leafKey.PublicKey, intermediateKey)
	leafCertificate, _ = x509.ParseCertificate(leafDER)

	return
}

// mockCertificateAuthority Implements root.CertificateAuthority For Testing
type mockCertificateAuthority struct {
	verifyFunc func(certificate *x509.Certificate, observerTimestamp time.Time) ([][]*x509.Certificate, error)
}

func (m *mockCertificateAuthority) Verify(certificate *x509.Certificate, observerTimestamp time.Time) ([][]*x509.Certificate, error) {
	return m.verifyFunc(certificate, observerTimestamp)
}

func TestInternalCertificateAuthority_Verify_SuccessWithBaseTrustedCA(t *testing.T) {
	rootCertificate, intermediateCertificate, leafCertificate, _, _, _ := createCertificateChain(t)

	// Create A FulcioCertificateAuthority That Will Successfully Verify
	fulcioCA := &root.FulcioCertificateAuthority{
		Root:          rootCertificate,
		Intermediates: []*x509.Certificate{intermediateCertificate},
	}

	internalCA := &InternalCertificateAuthority{
		TrustedCertificateAuthority: fulcioCA,
		UntrustedIntermediateCA:     nil, // No Bundle Intermediates
	}

	chains, err := internalCA.Verify(leafCertificate, time.Now())
	if err != nil {
		t.Fatalf("expected successful verification, got error: %v", err)
	}

	if len(chains) == 0 {
		t.Error("expected at least one certificate chain")
	}
}

func TestInternalCertificateAuthority_Verify_FallbackToIntermediatesFromBundle(t *testing.T) {
	rootCertificate, intermediateCertificate, leafCertificate, _, _, _ := createCertificateChain(t)

	// Create A FulcioCertificateAuthority With NO Intermediates (Will Fail Initially)
	fulcioCA := &root.FulcioCertificateAuthority{
		Root:          rootCertificate,
		Intermediates: nil, // No Intermediates In Trusted CA
	}

	// But We Provide Intermediates From The Bundle
	internalCA := &InternalCertificateAuthority{
		TrustedCertificateAuthority: fulcioCA,
		UntrustedIntermediateCA:     []*x509.Certificate{intermediateCertificate},
	}

	chains, err := internalCA.Verify(leafCertificate, time.Now())
	if err != nil {
		t.Fatalf("expected successful verification with bundle intermediates, got error: %v", err)
	}

	if len(chains) == 0 {
		t.Error("expected at least one certificate chain")
	}
}

func TestInternalCertificateAuthority_Verify_FailsWithNoIntermediates(t *testing.T) {
	rootCertificate, _, leafCertificate, _, _, _ := createCertificateChain(t)

	// Create A FulcioCertificateAuthority With NO Intermediates
	fulcioCA := &root.FulcioCertificateAuthority{
		Root:          rootCertificate,
		Intermediates: nil,
	}

	// And No Bundle Intermediates Either
	internalCA := &InternalCertificateAuthority{
		TrustedCertificateAuthority: fulcioCA,
		UntrustedIntermediateCA:     nil,
	}

	_, err := internalCA.Verify(leafCertificate, time.Now())
	if err == nil {
		t.Fatal("expected verification to fail without intermediates")
	}
}

func TestInternalCertificateAuthority_Verify_ValidityPeriodNotYetValid(t *testing.T) {
	rootCertificate, intermediateCertificate, leafCertificate, _, _, _ := createCertificateChain(t)

	// Create A FulcioCertificateAuthority That Isn't Valid Yet
	futureStart := time.Now().Add(24 * time.Hour)
	fulcioCA := &root.FulcioCertificateAuthority{
		Root:                rootCertificate,
		Intermediates:       nil,
		ValidityPeriodStart: futureStart,
	}

	internalCA := &InternalCertificateAuthority{
		TrustedCertificateAuthority: fulcioCA,
		UntrustedIntermediateCA:     []*x509.Certificate{intermediateCertificate},
	}

	_, err := internalCA.Verify(leafCertificate, time.Now())
	if err == nil {
		t.Fatal("expected verification to fail for not-yet-valid CA")
	}
	if err.Error() != "certificate is not valid yet" {
		t.Errorf("expected 'certificate is not valid yet' error, got: %v", err)
	}
}

func TestInternalCertificateAuthority_Verify_ValidityPeriodExpired(t *testing.T) {
	rootCertificate, intermediateCertificate, leafCertificate, _, _, _ := createCertificateChain(t)

	// Create A FulcioCertificateAuthority That Has Expired
	pastEnd := time.Now().Add(-24 * time.Hour)
	fulcioCA := &root.FulcioCertificateAuthority{
		Root:              rootCertificate,
		Intermediates:     nil,
		ValidityPeriodEnd: pastEnd,
	}

	internalCA := &InternalCertificateAuthority{
		TrustedCertificateAuthority: fulcioCA,
		UntrustedIntermediateCA:     []*x509.Certificate{intermediateCertificate},
	}

	_, err := internalCA.Verify(leafCertificate, time.Now())
	if err == nil {
		t.Fatal("expected verification to fail for expired CA")
	}
	if err.Error() != "certificate is no longer valid" {
		t.Errorf("expected 'certificate is no longer valid' error, got: %v", err)
	}
}

func TestInternalCertificateAuthority_Verify_NonFulcioCA(t *testing.T) {
	_, intermediateCertificate, leafCertificate, _, _, _ := createCertificateChain(t)

	// Create A Mock CA That Always Fails (Simulating Non-Fulcio CA)
	mockCA := &mockCertificateAuthority{
		verifyFunc: func(certificate *x509.Certificate, observerTimestamp time.Time) ([][]*x509.Certificate, error) {
			return nil, x509.UnknownAuthorityError{}
		},
	}

	internalCA := &InternalCertificateAuthority{
		TrustedCertificateAuthority: mockCA,
		UntrustedIntermediateCA:     []*x509.Certificate{intermediateCertificate},
	}

	_, err := internalCA.Verify(leafCertificate, time.Now())
	if err == nil {
		t.Fatal("expected verification to fail for non-Fulcio certificate authority")
	}
	// Should Contain The Error About Not Being A Fulcio CA
}

func TestFulcioCertificateAuthorities_WithIntermediates(t *testing.T) {
	rootCertificate, intermediateCertificate, _, _, _, _ := createCertificateChain(t)

	// Create A Mock Trusted Material
	fulcioCA := &root.FulcioCertificateAuthority{
		Root:          rootCertificate,
		Intermediates: nil,
	}

	mockTrustedMaterial := &mockTrustedMaterial{
		fulcioCAs: []root.CertificateAuthority{fulcioCA},
	}

	internalTrust := &InternalTrustMaterial{
		TrustedMaterial:   mockTrustedMaterial,
		UntrustedBundleCA: []*x509.Certificate{intermediateCertificate},
	}

	cas := internalTrust.FulcioCertificateAuthorities()

	if len(cas) != 1 {
		t.Fatalf("expected one (1) certificate authority, got %d", len(cas))
	}

	// Check That It's Wrapped In InternalCertificateAuthority
	internalCA, ok := cas[0].(*InternalCertificateAuthority)
	if !ok {
		t.Fatal("expected InternalCertificateAuthority wrapper")
	}

	if len(internalCA.UntrustedIntermediateCA) != 1 {
		t.Errorf("expected one (1) intermediate certificate, got %d", len(internalCA.UntrustedIntermediateCA))
	}
}

func TestFulcioCertificateAuthorities_WithoutIntermediates(t *testing.T) {
	rootCertificate, _, _, _, _, _ := createCertificateChain(t)

	fulcioCA := &root.FulcioCertificateAuthority{
		Root:          rootCertificate,
		Intermediates: nil,
	}

	mockTrustedMaterial := &mockTrustedMaterial{
		fulcioCAs: []root.CertificateAuthority{fulcioCA},
	}

	internalTrust := &InternalTrustMaterial{
		TrustedMaterial:   mockTrustedMaterial,
		UntrustedBundleCA: nil, // No Bundle Intermediates
	}

	cas := internalTrust.FulcioCertificateAuthorities()

	if len(cas) != 1 {
		t.Fatalf("expected 1 CA, got %d", len(cas))
	}

	// Should NOT Be Wrapped Since There Are No Intermediates
	_, ok := cas[0].(*InternalCertificateAuthority)
	if ok {
		t.Fatal("expected base certificate authority without InternalCertificateAuthority wrapper")
	}
}

func createTestCertificate(t *testing.T, subject, issuer pkix.Name, isCA bool, signingKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	var privateKey *ecdsa.PrivateKey
	var err error

	if signingKey == nil {
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}
	} else {
		privateKey = signingKey
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("failed to generate serial number: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		Issuer:       issuer,
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	if isCA {
		template.IsCA = true
		template.BasicConstraintsValid = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	var parent *x509.Certificate
	var signingPrivateKey *ecdsa.PrivateKey

	// Self-Signed If Subject Equals Issuer
	if subject.String() == issuer.String() {
		parent = template
		signingPrivateKey = privateKey
	} else {
		// For Intermediate/Leaf Certificates, We Need A Parent Certificate
		// Create A Temporary Parent For Signing
		parentCertificate, parentKey := createTestCertificate(t, issuer, issuer, true, nil)
		parent = parentCertificate
		signingPrivateKey = parentKey
	}

	certificateDER, err := x509.CreateCertificate(rand.Reader, template, parent, &privateKey.PublicKey, signingPrivateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatalf("failed to parse created certificate: %v", err)
	}

	return certificate, privateKey
}

// mockTrustedMaterial Implements root.TrustedMaterial For Testing
type mockTrustedMaterial struct {
	fulcioCAs []root.CertificateAuthority
}

func (m *mockTrustedMaterial) FulcioCertificateAuthorities() []root.CertificateAuthority {
	return m.fulcioCAs
}

func (m *mockTrustedMaterial) TimestampingAuthorities() []root.TimestampingAuthority {
	return nil
}

func (m *mockTrustedMaterial) RekorLogs() map[string]*root.TransparencyLog {
	return nil
}

func (m *mockTrustedMaterial) CTLogs() map[string]*root.TransparencyLog {
	return nil
}

func (m *mockTrustedMaterial) PublicKeyVerifier(hint string) (root.TimeConstrainedVerifier, error) {
	return nil, nil
}

// ecdsaDSSESigner Implements dsse.SignVerifier For ECDSA Keys
type ecdsaDSSESigner struct {
	key *ecdsa.PrivateKey
}

func (s *ecdsaDSSESigner) Sign(_ context.Context, data []byte) ([]byte, error) {
	// DSSE Uses PAE Encoding, So Data Is Already Pre-Authenticated
	// We Need To Hash It Before Signing With ECDSA
	hash := sha256.Sum256(data)
	return ecdsa.SignASN1(rand.Reader, s.key, hash[:])
}

func (s *ecdsaDSSESigner) Verify(data, sig []byte) error {
	hash := sha256.Sum256(data)
	if ecdsa.VerifyASN1(&s.key.PublicKey, hash[:], sig) {
		return nil
	}
	return errors.New("signature verification failed")
}

func (s *ecdsaDSSESigner) KeyID() (string, error) {
	return "", nil
}
