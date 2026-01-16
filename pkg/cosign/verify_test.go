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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag/conv"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	ggcrlayout "github.com/google/go-containerregistry/pkg/v1/layout"
	ggcrmutate "github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	ggcrstatic "github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/v3/internal/pkg/cosign/payload"
	"github.com/sigstore/cosign/v3/internal/pkg/cosign/rekor/mock"
	"github.com/sigstore/cosign/v3/internal/pkg/cosign/tsa"
	tsaMock "github.com/sigstore/cosign/v3/internal/pkg/cosign/tsa/mock"
	"github.com/sigstore/cosign/v3/internal/test"
	"github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/sigstore/cosign/v3/pkg/oci/layout"
	"github.com/sigstore/cosign/v3/pkg/oci/mutate"
	"github.com/sigstore/cosign/v3/pkg/oci/signed"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	"github.com/sigstore/cosign/v3/pkg/types"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	rtypes "github.com/sigstore/rekor/pkg/types"
	hashedrekord_v001 "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
	"github.com/sigstore/sigstore/pkg/tuf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/transparency-dev/merkle/rfc6962"
)

type mockVerifier struct {
	shouldErr bool
}

func (m *mockVerifier) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) { //nolint: revive
	return nil, nil
}

func (m *mockVerifier) VerifySignature(signature, message io.Reader, opts ...signature.VerifyOption) error { //nolint: revive
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

func (m *mockAttestation) Base64Signature() (string, error) {
	b, err := json.Marshal(m.payload)
	return string(b), err
}

func appendSlices(slices [][]byte) []byte {
	var tmp []byte
	for _, s := range slices {
		tmp = append(tmp, s...)
	}
	return tmp
}

func Test_verifyOCIAttestation(t *testing.T) {
	stmt, err := json.Marshal(in_toto.ProvenanceStatementSLSA02{})
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
	leafCert, privKey, _ := test.GenerateLeafCert("subject@mail.com", "oidc-issuer", subCert, subKey)
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
	verified, err := VerifyImageSignature(context.TODO(), ociSig, v1.Hash{},
		&CheckOpts{
			RootCerts:  rootPool,
			IgnoreSCT:  true,
			IgnoreTlog: true,
			Identities: []Identity{{Subject: "subject@mail.com", Issuer: "oidc-issuer"}}})
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
	leafCert, privKey, _ := test.GenerateLeafCert("subject@mail.com", "oidc-issuer", subCert3, subKey3)
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
	verified, err := VerifyImageSignature(context.TODO(), ociSig, v1.Hash{}, &CheckOpts{
		RootCerts: rootPool,
		IgnoreSCT: true, IgnoreTlog: true,
		Identities: []Identity{{Subject: "subject@mail.com", Issuer: "oidc-issuer"}}})
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

func CreateTestBundle(ctx context.Context, t *testing.T, rekor signature.Signer, leaf []byte) *bundle.RekorBundle {
	// generate log ID according to rekor public key
	pk, _ := rekor.PublicKey(nil)
	keyID, _ := GetTransparencyLogID(pk)
	pyld := bundle.RekorPayload{
		Body:           base64.StdEncoding.EncodeToString(leaf),
		IntegratedTime: time.Now().Unix(),
		LogIndex:       693591,
		LogID:          keyID,
	}
	// Sign with root.
	signature := signEntry(ctx, t, rekor, pyld)
	b := &bundle.RekorBundle{
		SignedEntryTimestamp: strfmt.Base64(signature),
		Payload:              pyld,
	}
	return b
}

func Test_verifySignaturesErrNoSignaturesFound(t *testing.T) {
	_, _, err := verifySignatures(context.Background(), &fakeOCISignatures{}, v1.Hash{}, nil)
	var e *ErrNoSignaturesFound
	if !errors.As(err, &e) {
		t.Fatalf("%T{%q} is not a %T", err, err, &ErrNoSignaturesFound{})
	}
}

func Test_verifySignaturesErrNoMatchingSignatures(t *testing.T) {
	rootCert, rootKey, _ := test.GenerateRootCa()
	subCert, subKey, _ := test.GenerateSubordinateCa(rootCert, rootKey)
	leafCert, privKey, _ := test.GenerateLeafCert("subject@mail.com", "oidc-issuer", subCert, subKey)
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
	_, _, err := verifySignatures(context.Background(), &fakeOCISignatures{signatures: []oci.Signature{ociSig}}, v1.Hash{}, &CheckOpts{
		RootCerts:  rootPool,
		IgnoreSCT:  true,
		IgnoreTlog: true,
		Identities: []Identity{{Subject: "another-subject@mail.com", Issuer: "oidc-issuer"}}})

	var e *ErrNoMatchingSignatures
	if !errors.As(err, &e) {
		t.Fatalf("%T{%q} is not a %T", err, err, &ErrNoMatchingSignatures{})
	}
}

func TestVerifyImageSignatureWithNoChain(t *testing.T) {
	ctx := context.Background()
	rootCert, rootKey, _ := test.GenerateRootCa()
	sv, _, err := signature.NewECDSASignerVerifier(elliptic.P256(), rand.Reader, crypto.SHA256)
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}

	leafCert, privKey, _ := test.GenerateLeafCert("subject@mail.com", "oidc-issuer", rootCert, rootKey)
	pemLeaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Raw})

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	payload := []byte{1, 2, 3, 4}
	h := sha256.Sum256(payload)
	signature, _ := privKey.Sign(rand.Reader, h[:], crypto.SHA256)

	// Create a fake bundle
	pe, _ := proposedEntries(base64.StdEncoding.EncodeToString(signature), payload, pemLeaf)
	entry, _ := rtypes.UnmarshalEntry(pe[0])
	leaf, _ := entry.Canonicalize(ctx)
	rekorBundle := CreateTestBundle(ctx, t, sv, leaf)
	pemBytes, _ := cryptoutils.MarshalPublicKeyToPEM(sv.Public())
	rekorPubKeys := NewTrustedTransparencyLogPubKeys()
	rekorPubKeys.AddTransparencyLogPubKey(pemBytes, tuf.Active)

	opts := []static.Option{static.WithCertChain(pemLeaf, []byte{}), static.WithBundle(rekorBundle)}
	ociSig, _ := static.NewSignature(payload, base64.StdEncoding.EncodeToString(signature), opts...)

	verified, err := VerifyImageSignature(context.TODO(), ociSig, v1.Hash{},
		&CheckOpts{
			RootCerts:    rootPool,
			IgnoreSCT:    true,
			Identities:   []Identity{{Subject: "subject@mail.com", Issuer: "oidc-issuer"}},
			RekorPubKeys: &rekorPubKeys})
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	if verified == false {
		t.Fatalf("expected verified=true, got verified=false")
	}
}

func TestVerifyImageSignatureWithKeyAndCert(t *testing.T) {
	ctx := context.Background()
	rootCert, rootKey, _ := test.GenerateRootCa()
	sv, _, err := signature.NewECDSASignerVerifier(elliptic.P256(), rand.Reader, crypto.SHA256)
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}

	leafCert, privKey, _ := test.GenerateLeafCert("subject@mail.com", "oidc-issuer", rootCert, rootKey)
	pemLeaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Raw})

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	payload := []byte{1, 2, 3, 4}
	h := sha256.Sum256(payload)
	sig, _ := privKey.Sign(rand.Reader, h[:], crypto.SHA256)

	// Create a fake bundle
	pe, _ := proposedEntries(base64.StdEncoding.EncodeToString(sig), payload, pemLeaf)
	entry, _ := rtypes.UnmarshalEntry(pe[0])
	leaf, _ := entry.Canonicalize(ctx)
	rekorBundle := CreateTestBundle(ctx, t, sv, leaf)
	pemBytes, _ := cryptoutils.MarshalPublicKeyToPEM(sv.Public())
	rekorPubKeys := NewTrustedTransparencyLogPubKeys()
	rekorPubKeys.AddTransparencyLogPubKey(pemBytes, tuf.Active)

	opts := []static.Option{static.WithCertChain(pemLeaf, []byte{}), static.WithBundle(rekorBundle)}
	ociSig, _ := static.NewSignature(payload, base64.StdEncoding.EncodeToString(sig), opts...)

	leafSV, err := signature.LoadECDSASignerVerifier(privKey, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	verified, err := VerifyImageSignature(context.TODO(), ociSig, v1.Hash{},
		&CheckOpts{
			SigVerifier:  leafSV,
			RootCerts:    rootPool,
			IgnoreSCT:    true,
			Identities:   []Identity{{Subject: "subject@mail.com", Issuer: "oidc-issuer"}},
			RekorPubKeys: &rekorPubKeys})
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	if verified == false {
		t.Fatalf("expected verified=true, got verified=false")
	}
}

func TestVerifyImageSignatureWithInvalidPublicKeyType(t *testing.T) {
	ctx := context.Background()
	rootCert, rootKey, _ := test.GenerateRootCa()
	sv, _, err := signature.NewECDSASignerVerifier(elliptic.P256(), rand.Reader, crypto.SHA256)
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}

	leafCert, privKey, _ := test.GenerateLeafCert("subject@mail.com", "oidc-issuer", rootCert, rootKey)
	pemLeaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Raw})

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	payload := []byte{1, 2, 3, 4}
	h := sha256.Sum256(payload)
	signature, _ := privKey.Sign(rand.Reader, h[:], crypto.SHA256)

	// Create a fake bundle
	pe, _ := proposedEntries(base64.StdEncoding.EncodeToString(signature), payload, pemLeaf)
	entry, _ := rtypes.UnmarshalEntry(pe[0])
	leaf, _ := entry.Canonicalize(ctx)
	rekorBundle := CreateTestBundle(ctx, t, sv, leaf)
	pemBytes, _ := cryptoutils.MarshalPublicKeyToPEM(sv.Public())
	rekorPubKeys := NewTrustedTransparencyLogPubKeys()
	// Add one valid key here.
	rekorPubKeys.AddTransparencyLogPubKey(pemBytes, tuf.Active)

	opts := []static.Option{static.WithCertChain(pemLeaf, []byte{}), static.WithBundle(rekorBundle)}
	ociSig, _ := static.NewSignature(payload, base64.StdEncoding.EncodeToString(signature), opts...)

	// Then try to validate with keys that are not ecdsa.PublicKey and should
	// fail.
	var rsaPrivKey crypto.PrivateKey
	rsaPrivKey, err = rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("Unable to create RSA test key: %v", err)
	}
	var signer crypto.Signer
	var ok bool
	if signer, ok = rsaPrivKey.(crypto.Signer); !ok {
		t.Fatalf("Unable to create signer out of RSA test key: %v", err)
	}
	rsaPEM, err := cryptoutils.MarshalPublicKeyToPEM(signer.Public())
	if err != nil {
		t.Fatalf("Unable to marshal RSA test key: %v", err)
	}
	if err = rekorPubKeys.AddTransparencyLogPubKey(rsaPEM, tuf.Active); err != nil {
		t.Fatalf("failed to add RSA key to transparency log public keys: %v", err)
	}
	verified, err := VerifyImageSignature(context.TODO(), ociSig, v1.Hash{},
		&CheckOpts{
			RootCerts:    rootPool,
			IgnoreSCT:    true,
			Identities:   []Identity{{Subject: "subject@mail.com", Issuer: "oidc-issuer"}},
			RekorPubKeys: &rekorPubKeys})
	if err == nil {
		t.Fatal("expected error got none")
	}
	if !strings.Contains(err.Error(), "is not type ecdsa.PublicKey") {
		t.Errorf("did not get expected failure message, wanted 'is not type ecdsa.PublicKey' got: %v", err)
	}
	if verified == true {
		t.Fatalf("expected verified=false, got verified=true")
	}
}

func TestVerifyImageSignatureWithOnlyRoot(t *testing.T) {
	rootCert, rootKey, _ := test.GenerateRootCa()
	leafCert, privKey, _ := test.GenerateLeafCert("subject@mail.com", "oidc-issuer", rootCert, rootKey)
	pemRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Raw})
	pemLeaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Raw})

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	payload := []byte{1, 2, 3, 4}
	h := sha256.Sum256(payload)
	signature, _ := privKey.Sign(rand.Reader, h[:], crypto.SHA256)

	ociSig, _ := static.NewSignature(payload, base64.StdEncoding.EncodeToString(signature), static.WithCertChain(pemLeaf, pemRoot))
	verified, err := VerifyImageSignature(context.TODO(), ociSig, v1.Hash{},
		&CheckOpts{
			RootCerts:  rootPool,
			IgnoreSCT:  true,
			Identities: []Identity{{Subject: "subject@mail.com", Issuer: "oidc-issuer"}},
			IgnoreTlog: true})
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
	leafCert, privKey, _ := test.GenerateLeafCert("subject@mail.com", "oidc-issuer", subCert, subKey)
	pemRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Raw})
	pemLeaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Raw})

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	payload := []byte{1, 2, 3, 4}
	h := sha256.Sum256(payload)
	signature, _ := privKey.Sign(rand.Reader, h[:], crypto.SHA256)

	ociSig, _ := static.NewSignature(payload, base64.StdEncoding.EncodeToString(signature), static.WithCertChain(pemLeaf, pemRoot))
	verified, err := VerifyImageSignature(context.TODO(), ociSig, v1.Hash{},
		&CheckOpts{
			RootCerts:  rootPool,
			IgnoreSCT:  true,
			Identities: []Identity{{Subject: "subject@mail.com", Issuer: "oidc-issuer"}},
			IgnoreTlog: true})
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

func TestVerifyImageSignatureWithExistingSub(t *testing.T) {
	rootCert, rootKey, _ := test.GenerateRootCa()
	subCert, subKey, _ := test.GenerateSubordinateCa(rootCert, rootKey)
	leafCert, privKey, _ := test.GenerateLeafCert("subject@mail.com", "oidc-issuer", subCert, subKey)
	pemRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Raw})
	pemSub := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: subCert.Raw})
	pemLeaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Raw})

	otherSubCert, _, _ := test.GenerateSubordinateCa(rootCert, rootKey)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)
	subPool := x509.NewCertPool()
	// Load in different sub cert so the chain doesn't verify
	rootPool.AddCert(otherSubCert)

	payload := []byte{1, 2, 3, 4}
	h := sha256.Sum256(payload)
	signature, _ := privKey.Sign(rand.Reader, h[:], crypto.SHA256)

	ociSig, _ := static.NewSignature(payload,
		base64.StdEncoding.EncodeToString(signature),
		static.WithCertChain(pemLeaf, appendSlices([][]byte{pemSub, pemRoot})))
	verified, err := VerifyImageSignature(context.TODO(), ociSig, v1.Hash{},
		&CheckOpts{
			RootCerts:         rootPool,
			IntermediateCerts: subPool,
			IgnoreSCT:         true,
			Identities:        []Identity{{Subject: "subject@mail.com", Issuer: "oidc-issuer"}},
			IgnoreTlog:        true})
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

var (
	lea = models.LogEntryAnon{
		Attestation:    &models.LogEntryAnonAttestation{},
		Body:           base64.StdEncoding.EncodeToString([]byte("asdf")),
		IntegratedTime: new(int64),
		LogID:          new(string),
		LogIndex:       new(int64),
		Verification: &models.LogEntryAnonVerification{
			InclusionProof: &models.InclusionProof{
				RootHash: new(string),
				TreeSize: new(int64),
				LogIndex: new(int64),
			},
		},
	}
	data = models.LogEntry{
		uuid(lea): lea,
	}
)

// uuid generates the UUID for the given LogEntry.
// This is effectively a reimplementation of
// pkg/cosign/tlog.go -> verifyUUID / ComputeLeafHash, but separated
// to avoid a circular dependency.
// TODO?: Perhaps we should refactor the tlog libraries into a separate
// package?
func uuid(e models.LogEntryAnon) string {
	entryBytes, err := base64.StdEncoding.DecodeString(e.Body.(string))
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(rfc6962.DefaultHasher.HashLeaf(entryBytes))
}

func TestImageSignatureVerificationWithRekor(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Generate ECDSA signer and public key for signing the blob.
	signer, publicKey := generateSigner(t)
	blob, blobSignature, blobSignatureBase64 := generateBlobSignature(t, signer)

	// Create an OCI signature which will be verified.
	ociSignature, err := static.NewSignature(blob, blobSignatureBase64)
	require.NoError(t, err, "error creating OCI signature")

	// Set up mock Rekor signer and log ID.
	rekorSigner, rekorPublicKey := generateSigner(t)
	logID := calculateLogID(t, rekorPublicKey)

	// Create a mock Rekor log entry to simulate Rekor behavior.
	rekorEntry := createRekorEntry(ctx, t, logID, rekorSigner, blob, blobSignature, publicKey)

	// Mock Rekor client to return the mock log entry for verification.
	mockClient := &client.Rekor{
		Entries: &mockEntriesClient{
			searchLogQueryFunc: func(_ *entries.SearchLogQueryParams, _ ...entries.ClientOption) (*entries.SearchLogQueryOK, error) {
				return &entries.SearchLogQueryOK{
					Payload: []models.LogEntry{*rekorEntry},
				}, nil
			},
		},
	}

	// Define trusted Rekor public keys for verification.
	trustedRekorPubKeys := &TrustedTransparencyLogPubKeys{
		Keys: map[string]TransparencyLogPubKey{
			logID: {
				PubKey: rekorPublicKey,
				Status: tuf.Active,
			},
		},
	}

	// Generate non-matching public key for failure test cases.
	_, nonMatchingPublicKey := generateSigner(t)
	nonMatchingRekorPubKeys := &TrustedTransparencyLogPubKeys{
		Keys: map[string]TransparencyLogPubKey{
			logID: {
				PubKey: nonMatchingPublicKey,
				Status: tuf.Active,
			},
		},
	}

	tests := []struct {
		name        string
		checkOpts   CheckOpts
		rekorClient *client.Rekor
		expectError bool
		errorMsg    string
	}{
		{
			name: "Verification succeeds with valid Rekor public keys",
			checkOpts: CheckOpts{
				SigVerifier:  signer,
				RekorClient:  mockClient,
				RekorPubKeys: trustedRekorPubKeys,
				Identities:   []Identity{{Subject: "subject@mail.com", Issuer: "oidc-issuer"}},
			},
			rekorClient: mockClient,
			expectError: false,
		},
		{
			name: "Verification fails with no Rekor public keys",
			checkOpts: CheckOpts{
				SigVerifier: signer,
				RekorClient: mockClient,
				Identities:  []Identity{{Subject: "subject@mail.com", Issuer: "oidc-issuer"}},
			},
			rekorClient: mockClient,
			expectError: true,
			errorMsg:    "no valid tlog entries found no trusted rekor public keys provided",
		},
		{
			name: "Verification fails with non-matching Rekor public keys",
			checkOpts: CheckOpts{
				SigVerifier:  signer,
				RekorClient:  mockClient,
				RekorPubKeys: nonMatchingRekorPubKeys,
				Identities:   []Identity{{Subject: "subject@mail.com", Issuer: "oidc-issuer"}},
			},
			rekorClient: mockClient,
			expectError: true,
			errorMsg:    "verifying signedEntryTimestamp: unable to verify SET",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bundleVerified, err := VerifyImageSignature(ctx, ociSignature, v1.Hash{}, &tt.checkOpts)
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
				assert.True(t, bundleVerified, "bundle verification failed")
			}
		})
	}
}

func TestVerifyImageSignatureWithSigVerifierAndTSA(t *testing.T) {
	client, err := tsaMock.NewTSAClient((tsaMock.TSAClientOptions{Time: time.Now()}))
	if err != nil {
		t.Fatal(err)
	}

	sv, _, err := signature.NewDefaultECDSASignerVerifier()
	if err != nil {
		t.Fatalf("error generating verifier: %v", err)
	}
	payloadSigner := payload.NewSigner(sv)
	testSigner := tsa.NewSigner(payloadSigner, client)

	certChainPEM, err := cryptoutils.MarshalCertificatesToPEM(client.CertChain)
	if err != nil {
		t.Fatalf("unexpected error marshalling cert chain: %v", err)
	}

	leaves, intermediates, roots, err := tsa.SplitPEMCertificateChain(certChainPEM)
	if err != nil {
		t.Fatal("error splitting response into certificate chain")
	}

	payload := []byte{1, 2, 3, 4}
	sig, _, err := testSigner.Sign(context.Background(), bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("error signing the payload with the tsa client server: %v", err)
	}
	if bundleVerified, err := VerifyImageSignature(context.TODO(), sig, v1.Hash{}, &CheckOpts{
		SigVerifier:                 sv,
		TSACertificate:              leaves[0],
		TSAIntermediateCertificates: intermediates,
		TSARootCertificates:         roots,
		IgnoreTlog:                  true,
	}); err != nil || bundleVerified { // bundle is not verified since there's no Rekor bundle
		t.Fatalf("unexpected error while verifying signature, got %v", err)
	}
}

func TestVerifyImageSignatureWithSigVerifierAndRekorTSA(t *testing.T) {
	// Add a fake rekor client - this makes it look like there's a matching
	// tlog entry for the signature during validation (even though it does not
	// match the underlying data / key)
	mClient := new(client.Rekor)
	mClient.Entries = &mock.EntriesClient{
		Entries: []*models.LogEntry{&data},
	}

	client, err := tsaMock.NewTSAClient((tsaMock.TSAClientOptions{Time: time.Now()}))
	if err != nil {
		t.Fatal(err)
	}
	sv, _, err := signature.NewDefaultECDSASignerVerifier()
	if err != nil {
		t.Fatalf("error generating verifier: %v", err)
	}
	payloadSigner := payload.NewSigner(sv)
	tsaSigner := tsa.NewSigner(payloadSigner, client)

	certChainPEM, err := cryptoutils.MarshalCertificatesToPEM(client.CertChain)
	if err != nil {
		t.Fatalf("unexpected error marshalling cert chain: %v", err)
	}

	leaves, intermediates, roots, err := tsa.SplitPEMCertificateChain(certChainPEM)
	if err != nil {
		t.Fatal("error splitting response into certificate chain")
	}

	payload := []byte{1, 2, 3, 4}
	sig, _, err := tsaSigner.Sign(context.Background(), bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("error signing the payload with the rekor and tsa clients: %v", err)
	}
	if _, err := VerifyImageSignature(context.TODO(), sig, v1.Hash{}, &CheckOpts{
		SigVerifier:                 sv,
		TSACertificate:              leaves[0],
		TSAIntermediateCertificates: intermediates,
		TSARootCertificates:         roots,
		RekorClient:                 mClient,
	}); err == nil || !strings.Contains(err.Error(), "no trusted rekor public keys provided") {
		// TODO(wlynch): This is a weak test, since this is really failing because
		// there is no inclusion proof for the Rekor entry rather than failing to
		// validate the Rekor public key itself. At the very least this ensures
		// that we're hitting tlog validation during signature checking,
		// but we should look into improving this once there is an in-memory
		// Rekor client that is capable of performing inclusion proof validation
		// in unit tests.
		t.Fatalf("expected error while verifying signature, got %s", err)
	}
}

func TestVerifyImageSignatureWithMismatchedBundleAndTrustedRoot(t *testing.T) {
	ctx := context.Background()
	var ca root.FulcioCertificateAuthority
	rootCert, rootKey, _ := test.GenerateRootCa()
	ca.Root = rootCert
	sv, _, err := signature.NewECDSASignerVerifier(elliptic.P256(), rand.Reader, crypto.SHA256)
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}

	leafCert, privKey, _ := test.GenerateLeafCert("subject@mail.com", "oidc-issuer", rootCert, rootKey)
	pemLeaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Raw})

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	payload := []byte{1, 2, 3, 4}
	h := sha256.Sum256(payload)
	signature1, _ := privKey.Sign(rand.Reader, h[:], crypto.SHA256)

	// Create a fake bundle
	pe, _ := proposedEntries(base64.StdEncoding.EncodeToString(signature1), payload, pemLeaf)
	entry, _ := rtypes.UnmarshalEntry(pe[0])
	leaf, _ := entry.Canonicalize(ctx)
	rekorBundle := CreateTestBundle(ctx, t, sv, leaf)
	pemBytes, _ := cryptoutils.MarshalPublicKeyToPEM(sv.Public())
	rekorPubKeys := NewTrustedTransparencyLogPubKeys()
	rekorPubKeys.AddTransparencyLogPubKey(pemBytes, tuf.Active)

	tlogs := make(map[string]*root.TransparencyLog)
	for k, v := range rekorPubKeys.Keys {
		tlogs[k] = &root.TransparencyLog{PublicKey: v.PubKey, HashFunc: crypto.SHA256, ValidityPeriodStart: time.Now().Add(-1 * time.Minute)}
	}

	trustedRoot, err := root.NewTrustedRoot(root.TrustedRootMediaType01, []root.CertificateAuthority{&ca}, nil, nil, tlogs)
	if err != nil {
		t.Fatal(err)
	}

	// Create a different bundle for a different signature
	signature2, _ := privKey.Sign(rand.Reader, h[:], crypto.SHA256)
	pe2, _ := proposedEntries(base64.StdEncoding.EncodeToString(signature2), payload, pemLeaf)
	entry2, _ := rtypes.UnmarshalEntry(pe2[0])
	leaf2, _ := entry2.Canonicalize(ctx)
	rekorBundle2 := CreateTestBundle(ctx, t, sv, leaf2)

	opts := []static.Option{static.WithCertChain(pemLeaf, []byte{}), static.WithBundle(rekorBundle2)}
	// Create a signed entity for the original signature but with the wrong bundle for that signature
	ociSig, _ := static.NewSignature(payload, base64.StdEncoding.EncodeToString(signature1), opts...)

	_, err = VerifyImageSignature(context.TODO(), ociSig, v1.Hash{},
		&CheckOpts{
			RootCerts:       rootPool,
			IgnoreSCT:       true,
			Identities:      []Identity{{Subject: "subject@mail.com", Issuer: "oidc-issuer"}},
			TrustedMaterial: trustedRoot})
	if err == nil || !strings.Contains(err.Error(), "signature in bundle does not match signature being verified") {
		t.Fatalf("expected error for mismatched signature and bundle, got %v", err)
	}

	// Create a signed entity with a different key from the bundle
	leafCert2, _, _ := test.GenerateLeafCert("subject@mail.com", "oidc-issuer", rootCert, rootKey)
	pemLeaf2 := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert2.Raw})

	opts = []static.Option{static.WithCertChain(pemLeaf2, []byte{}), static.WithBundle(rekorBundle)}
	ociSig, _ = static.NewSignature(payload, base64.StdEncoding.EncodeToString(signature1), opts...)

	_, err = VerifyImageSignature(context.TODO(), ociSig, v1.Hash{},
		&CheckOpts{
			RootCerts:       rootPool,
			IgnoreSCT:       true,
			Identities:      []Identity{{Subject: "subject@mail.com", Issuer: "oidc-issuer"}},
			TrustedMaterial: trustedRoot})
	if err == nil || !strings.Contains(err.Error(), "error verifying bundle: comparing public key PEMs") {
		t.Fatal(err)
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
		RootCerts:  rootPool,
		IgnoreSCT:  true,
		Identities: []Identity{{Subject: subject, Issuer: oidcIssuer}},
	}

	_, err := ValidateAndUnpackCert(leafCert, co)
	if err != nil {
		t.Errorf("ValidateAndUnpackCert expected no error, got err = %v", err)
	}
	err = CheckCertificatePolicy(leafCert, co)
	if err != nil {
		t.Errorf("CheckCertificatePolicy expected no error, got err = %v", err)
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
		RootCerts:  rootPool,
		IgnoreSCT:  true,
		Identities: []Identity{{Subject: subject, Issuer: oidcIssuer}},
	}

	_, err := ValidateAndUnpackCert(leafCert, co)
	if err != nil {
		t.Errorf("ValidateAndUnpackCert expected no error, got err = %v", err)
	}
	err = CheckCertificatePolicy(leafCert, co)
	if err != nil {
		t.Errorf("CheckCertificatePolicy expected no error, got err = %v", err)
	}
}

func TestValidateAndUnpackCertWithoutRequiredSCT(t *testing.T) {
	subject := "email@email"
	oidcIssuer := "https://accounts.google.com"

	rootCert, rootKey, _ := test.GenerateRootCa()
	leafCert, _, _ := test.GenerateLeafCert(subject, oidcIssuer, rootCert, rootKey)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	co := &CheckOpts{
		RootCerts:  rootPool,
		Identities: []Identity{{Subject: subject, Issuer: oidcIssuer}},
		// explicitly set to false
		IgnoreSCT: false,
	}

	_, err := ValidateAndUnpackCert(leafCert, co)
	require.Contains(t, err.Error(), "certificate does not include required embedded SCT")
}

func TestValidateAndUnpackCertSuccessWithDnsSan(t *testing.T) {
	subject := "example.com"
	oidcIssuer := "https://accounts.google.com"

	rootCert, rootKey, _ := test.GenerateRootCa()
	leafCert, _, _ := test.GenerateLeafCertWithSubjectAlternateNames(
		[]string{subject}, /* dnsNames */
		nil,               /* emailAddresses */
		nil,               /* ipAddresses */
		nil,               /* uris */
		oidcIssuer,        /* oidcIssuer */
		rootCert,
		rootKey)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	co := &CheckOpts{
		RootCerts:  rootPool,
		Identities: []Identity{{Subject: subject, Issuer: oidcIssuer}},
		IgnoreSCT:  true,
	}

	_, err := ValidateAndUnpackCert(leafCert, co)
	if err != nil {
		t.Errorf("ValidateAndUnpackCert expected no error, got err = %v", err)
	}
	err = CheckCertificatePolicy(leafCert, co)
	if err != nil {
		t.Errorf("CheckCertificatePolicy expected no error, got err = %v", err)
	}
}

func TestValidateAndUnpackCertSuccessWithEmailSan(t *testing.T) {
	subject := "email@email"
	oidcIssuer := "https://accounts.google.com"

	rootCert, rootKey, _ := test.GenerateRootCa()
	leafCert, _, _ := test.GenerateLeafCertWithSubjectAlternateNames(
		nil,               /* dnsNames */
		[]string{subject}, /* emailAddresses */
		nil,               /* ipAddresses */
		nil,               /* uris */
		oidcIssuer,        /* oidcIssuer */
		rootCert,
		rootKey)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	co := &CheckOpts{
		RootCerts:  rootPool,
		Identities: []Identity{{Subject: subject, Issuer: oidcIssuer}},
		IgnoreSCT:  true,
	}

	_, err := ValidateAndUnpackCert(leafCert, co)
	if err != nil {
		t.Errorf("ValidateAndUnpackCert expected no error, got err = %v", err)
	}
	err = CheckCertificatePolicy(leafCert, co)
	if err != nil {
		t.Errorf("CheckCertificatePolicy expected no error, got err = %v", err)
	}
}

func TestValidateAndUnpackCertSuccessWithIpAddressSan(t *testing.T) {
	subject := "127.0.0.1"
	oidcIssuer := "https://accounts.google.com"

	rootCert, rootKey, _ := test.GenerateRootCa()
	leafCert, _, _ := test.GenerateLeafCertWithSubjectAlternateNames(
		nil,                            /* dnsNames */
		nil,                            /* emailAddresses */
		[]net.IP{net.ParseIP(subject)}, /* ipAddresses */
		nil,                            /* uris */
		oidcIssuer,                     /* oidcIssuer */
		rootCert,
		rootKey)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	co := &CheckOpts{
		RootCerts:  rootPool,
		Identities: []Identity{{Subject: subject, Issuer: oidcIssuer}},
		IgnoreSCT:  true,
	}

	_, err := ValidateAndUnpackCert(leafCert, co)
	if err != nil {
		t.Errorf("ValidateAndUnpackCert expected no error, got err = %v", err)
	}
	err = CheckCertificatePolicy(leafCert, co)
	if err != nil {
		t.Errorf("CheckCertificatePolicy expected no error, got err = %v", err)
	}
}

func TestValidateAndUnpackCertSuccessWithUriSan(t *testing.T) {
	subject, _ := url.Parse("scheme://userinfo@host")
	oidcIssuer := "https://accounts.google.com"

	rootCert, rootKey, _ := test.GenerateRootCa()
	leafCert, _, _ := test.GenerateLeafCertWithSubjectAlternateNames(
		nil,                 /* dnsNames */
		nil,                 /* emailAddresses */
		nil,                 /* ipAddresses */
		[]*url.URL{subject}, /* uris */
		oidcIssuer,          /* oidcIssuer */
		rootCert,
		rootKey)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	co := &CheckOpts{
		RootCerts:  rootPool,
		Identities: []Identity{{Subject: "scheme://userinfo@host", Issuer: oidcIssuer}},
		IgnoreSCT:  true,
	}

	_, err := ValidateAndUnpackCert(leafCert, co)
	if err != nil {
		t.Errorf("ValidateAndUnpackCert expected no error, got err = %v", err)
	}
	err = CheckCertificatePolicy(leafCert, co)
	if err != nil {
		t.Errorf("CheckCertificatePolicy expected no error, got err = %v", err)
	}
}

func TestValidateAndUnpackCertSuccessWithOtherNameSan(t *testing.T) {
	// generate with OtherName, which will override other SANs
	subject := "subject-othername"
	ext, err := cryptoutils.MarshalOtherNameSAN(subject, true)
	if err != nil {
		t.Fatalf("error marshalling SANs: %v", err)
	}
	exts := []pkix.Extension{*ext}

	oidcIssuer := "https://accounts.google.com"

	rootCert, rootKey, _ := test.GenerateRootCa()
	leafCert, _, _ := test.GenerateLeafCert("unused", oidcIssuer, rootCert, rootKey, exts...)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	co := &CheckOpts{
		RootCerts:  rootPool,
		Identities: []Identity{{Subject: subject, Issuer: oidcIssuer}},
		IgnoreSCT:  true,
	}

	_, err = ValidateAndUnpackCert(leafCert, co)
	if err != nil {
		t.Errorf("ValidateAndUnpackCert expected no error, got err = %v", err)
	}
	err = CheckCertificatePolicy(leafCert, co)
	if err != nil {
		t.Errorf("CheckCertificatePolicy expected no error, got err = %v", err)
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
		RootCerts:  rootPool,
		Identities: []Identity{{Subject: subject, Issuer: oidcIssuer}},
		IgnoreSCT:  true,
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
		RootCerts:  rootPool,
		Identities: []Identity{{Subject: subject, Issuer: "other"}},
		IgnoreSCT:  true,
	}

	_, err := ValidateAndUnpackCert(leafCert, co)
	require.Contains(t, err.Error(), "none of the expected identities matched what was in the certificate")
	err = CheckCertificatePolicy(leafCert, co)
	require.Contains(t, err.Error(), "none of the expected identities matched what was in the certificate")
}

func TestValidateAndUnpackCertInvalidEmail(t *testing.T) {
	subject := "email@email"
	oidcIssuer := "https://accounts.google.com"

	rootCert, rootKey, _ := test.GenerateRootCa()
	leafCert, _, _ := test.GenerateLeafCert(subject, oidcIssuer, rootCert, rootKey)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	co := &CheckOpts{
		RootCerts:  rootPool,
		Identities: []Identity{{Subject: "other", Issuer: oidcIssuer}},
		IgnoreSCT:  true,
	}

	_, err := ValidateAndUnpackCert(leafCert, co)
	require.Contains(t, err.Error(), "none of the expected identities matched what was in the certificate")
	err = CheckCertificatePolicy(leafCert, co)
	require.Contains(t, err.Error(), "none of the expected identities matched what was in the certificate")
}

func TestValidateAndUnpackCertInvalidGithubWorkflowTrigger(t *testing.T) {
	subject := "email@email"
	oidcIssuer := "https://accounts.google.com"
	githubWorkFlowTrigger := "myTrigger"

	rootCert, rootKey, _ := test.GenerateRootCa()
	leafCert, _, _ := test.GenerateLeafCertWithGitHubOIDs(subject, oidcIssuer, githubWorkFlowTrigger, "", "", "", "", rootCert, rootKey)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	co := &CheckOpts{
		RootCerts:                 rootPool,
		Identities:                []Identity{{Subject: subject, Issuer: oidcIssuer}},
		CertGithubWorkflowTrigger: "otherTrigger",
		IgnoreSCT:                 true,
	}

	_, err := ValidateAndUnpackCert(leafCert, co)
	require.Contains(t, err.Error(), "expected GitHub Workflow Trigger not found in certificate")
	err = CheckCertificatePolicy(leafCert, co)
	require.Contains(t, err.Error(), "expected GitHub Workflow Trigger not found in certificate")
}

func TestValidateAndUnpackCertInvalidGithubWorkflowSHA(t *testing.T) {
	subject := "email@email"
	oidcIssuer := "https://accounts.google.com"
	githubWorkFlowSha := "mySHA"

	rootCert, rootKey, _ := test.GenerateRootCa()
	leafCert, _, _ := test.GenerateLeafCertWithGitHubOIDs(subject, oidcIssuer, "", githubWorkFlowSha, "", "", "", rootCert, rootKey)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	co := &CheckOpts{
		RootCerts:             rootPool,
		Identities:            []Identity{{Subject: subject, Issuer: oidcIssuer}},
		CertGithubWorkflowSha: "otherSHA",
		IgnoreSCT:             true,
	}

	_, err := ValidateAndUnpackCert(leafCert, co)
	require.Contains(t, err.Error(), "expected GitHub Workflow SHA not found in certificate")
	err = CheckCertificatePolicy(leafCert, co)
	require.Contains(t, err.Error(), "expected GitHub Workflow SHA not found in certificate")
}

func TestValidateAndUnpackCertInvalidGithubWorkflowName(t *testing.T) {
	subject := "email@email"
	oidcIssuer := "https://accounts.google.com"
	githubWorkFlowName := "myName"

	rootCert, rootKey, _ := test.GenerateRootCa()
	leafCert, _, _ := test.GenerateLeafCertWithGitHubOIDs(subject, oidcIssuer, "", "", githubWorkFlowName, "", "", rootCert, rootKey)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	co := &CheckOpts{
		RootCerts:              rootPool,
		Identities:             []Identity{{Subject: subject, Issuer: oidcIssuer}},
		CertGithubWorkflowName: "otherName",
		IgnoreSCT:              true,
	}

	_, err := ValidateAndUnpackCert(leafCert, co)
	require.Contains(t, err.Error(), "expected GitHub Workflow Name not found in certificate")
	err = CheckCertificatePolicy(leafCert, co)
	require.Contains(t, err.Error(), "expected GitHub Workflow Name not found in certificate")
}

func TestValidateAndUnpackCertInvalidGithubWorkflowRepository(t *testing.T) {
	subject := "email@email"
	oidcIssuer := "https://accounts.google.com"
	githubWorkFlowRepository := "myRepository"

	rootCert, rootKey, _ := test.GenerateRootCa()
	leafCert, _, _ := test.GenerateLeafCertWithGitHubOIDs(subject, oidcIssuer, "", "", "", githubWorkFlowRepository, "", rootCert, rootKey)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	co := &CheckOpts{
		RootCerts:                    rootPool,
		Identities:                   []Identity{{Subject: subject, Issuer: oidcIssuer}},
		CertGithubWorkflowRepository: "otherRepository",
		IgnoreSCT:                    true,
	}

	_, err := ValidateAndUnpackCert(leafCert, co)
	require.Contains(t, err.Error(), "expected GitHub Workflow Repository not found in certificate")
	err = CheckCertificatePolicy(leafCert, co)
	require.Contains(t, err.Error(), "expected GitHub Workflow Repository not found in certificate")
}

func TestValidateAndUnpackCertInvalidGithubWorkflowRef(t *testing.T) {
	subject := "email@email"
	oidcIssuer := "https://accounts.google.com"
	githubWorkFlowRef := "myRef"

	rootCert, rootKey, _ := test.GenerateRootCa()
	leafCert, _, _ := test.GenerateLeafCertWithGitHubOIDs(subject, oidcIssuer, "", "", "", "", githubWorkFlowRef, rootCert, rootKey)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	co := &CheckOpts{
		RootCerts:             rootPool,
		Identities:            []Identity{{Subject: subject, Issuer: oidcIssuer}},
		CertGithubWorkflowRef: "otherRef",
		IgnoreSCT:             true,
	}

	_, err := ValidateAndUnpackCert(leafCert, co)
	require.Contains(t, err.Error(), "expected GitHub Workflow Ref not found in certificate")
	err = CheckCertificatePolicy(leafCert, co)
	require.Contains(t, err.Error(), "expected GitHub Workflow Ref not found in certificate")
}

func TestValidateAndUnpackCertWithChainSuccess(t *testing.T) {
	subject := "email@email"
	oidcIssuer := "https://accounts.google.com"

	rootCert, rootKey, _ := test.GenerateRootCa()
	subCert, subKey, _ := test.GenerateSubordinateCa(rootCert, rootKey)
	leafCert, _, _ := test.GenerateLeafCert(subject, oidcIssuer, subCert, subKey)

	co := &CheckOpts{
		Identities: []Identity{{Subject: subject, Issuer: oidcIssuer}},
		IgnoreSCT:  true,
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
		Identities: []Identity{{Subject: subject, Issuer: oidcIssuer}},
		IgnoreSCT:  true,
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
		Identities: []Identity{{Subject: subject, Issuer: oidcIssuer}},
		IgnoreSCT:  true,
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
		Identities: []Identity{{Subject: subject, Issuer: oidcIssuer}},
		IgnoreSCT:  true,
	}

	_, err := ValidateAndUnpackCertWithChain(leafCert, []*x509.Certificate{rootCertOther}, co)
	if err == nil || !strings.Contains(err.Error(), "certificate signed by unknown authority") {
		t.Errorf("expected error without valid chain, got %v", err)
	}
}

func TestValidateAndUnpackCertWithIdentities(t *testing.T) {
	u, err := url.Parse("http://url.example.com")
	if err != nil {
		t.Fatal("failed to parse url", err)
	}
	emailSubject := "email@example.com"
	dnsSubjects := []string{"dnssubject.example.com"}
	ipSubjects := []net.IP{net.ParseIP("1.2.3.4")}
	uriSubjects := []*url.URL{u}
	otherName := "email!example.com"
	oidcIssuer := "https://accounts.google.com"

	tests := []struct {
		identities       []Identity
		wantErrSubstring string
		dnsNames         []string
		emailAddresses   []string
		ipAddresses      []net.IP
		uris             []*url.URL
		otherName        string
	}{
		{identities: nil /* No matches required, checks out */},
		{identities: []Identity{ // Strict match on both
			{Subject: emailSubject, Issuer: oidcIssuer}},
			emailAddresses: []string{emailSubject}},
		{identities: []Identity{ // just issuer
			{Issuer: oidcIssuer}},
			emailAddresses: []string{emailSubject}},
		{identities: []Identity{ // just subject
			{Subject: emailSubject}},
			emailAddresses: []string{emailSubject}},
		{identities: []Identity{ // mis-match
			{Subject: "wrongsubject", Issuer: oidcIssuer},
			{Subject: emailSubject, Issuer: "wrongissuer"}},
			emailAddresses:   []string{emailSubject},
			wantErrSubstring: "none of the expected identities matched"},
		{identities: []Identity{ // one good identity, other does not match
			{Subject: "wrongsubject", Issuer: "wrongissuer"},
			{Subject: emailSubject, Issuer: oidcIssuer}},
			emailAddresses: []string{emailSubject}},
		{identities: []Identity{ // illegal regex for subject
			{SubjectRegExp: "****", Issuer: oidcIssuer}},
			emailAddresses:   []string{emailSubject},
			wantErrSubstring: "malformed subject in identity"},
		{identities: []Identity{ // illegal regex for issuer
			{Subject: emailSubject, IssuerRegExp: "****"}},
			wantErrSubstring: "malformed issuer in identity"},
		{identities: []Identity{ // regex matches
			{SubjectRegExp: ".*example.com", IssuerRegExp: ".*accounts.google.*"}},
			emailAddresses:   []string{emailSubject},
			wantErrSubstring: ""},
		{identities: []Identity{ // regex matches dnsNames
			{SubjectRegExp: ".*ubject.example.com", IssuerRegExp: ".*accounts.google.*"}},
			dnsNames:         dnsSubjects,
			wantErrSubstring: ""},
		{identities: []Identity{ // regex matches ip
			{SubjectRegExp: "1.2.3.*", IssuerRegExp: ".*accounts.google.*"}},
			ipAddresses:      ipSubjects,
			wantErrSubstring: ""},
		{identities: []Identity{ // regex matches urls
			{SubjectRegExp: ".*url.examp.*", IssuerRegExp: ".*accounts.google.*"}},
			uris:             uriSubjects,
			wantErrSubstring: ""},
		{identities: []Identity{ // regex matches otherName
			{SubjectRegExp: ".*example.com", IssuerRegExp: ".*accounts.google.*"}},
			otherName:        otherName,
			wantErrSubstring: ""},
	}
	for _, tc := range tests {
		rootCert, rootKey, _ := test.GenerateRootCa()
		var leafCert *x509.Certificate
		if len(tc.otherName) == 0 {
			leafCert, _, _ = test.GenerateLeafCertWithSubjectAlternateNames(tc.dnsNames, tc.emailAddresses, tc.ipAddresses, tc.uris, oidcIssuer, rootCert, rootKey)
		} else {
			// generate with OtherName, which will override other SANs
			ext, err := cryptoutils.MarshalOtherNameSAN(tc.otherName, true)
			if err != nil {
				t.Fatalf("error marshalling SANs: %v", err)
			}
			exts := []pkix.Extension{*ext}
			leafCert, _, _ = test.GenerateLeafCert("unused", oidcIssuer, rootCert, rootKey, exts...)
		}

		rootPool := x509.NewCertPool()
		rootPool.AddCert(rootCert)

		co := &CheckOpts{
			RootCerts:  rootPool,
			Identities: tc.identities,
			IgnoreSCT:  true,
		}

		_, err := ValidateAndUnpackCert(leafCert, co)
		if err == nil && tc.wantErrSubstring != "" {
			t.Errorf("Expected error %s got none", tc.wantErrSubstring)
		} else if err != nil {
			if tc.wantErrSubstring == "" {
				t.Errorf("Did not expect an error, got err = %v", err)
			} else if !strings.Contains(err.Error(), tc.wantErrSubstring) {
				t.Errorf("Did not get the expected error %s, got err = %v", tc.wantErrSubstring, err)
			}
		}
		// Test CheckCertificatePolicy
		err = CheckCertificatePolicy(leafCert, co)
		if err == nil && tc.wantErrSubstring != "" {
			t.Errorf("Expected error %s got none", tc.wantErrSubstring)
		} else if err != nil {
			if tc.wantErrSubstring == "" {
				t.Errorf("Did not expect an error, got err = %v", err)
			} else if !strings.Contains(err.Error(), tc.wantErrSubstring) {
				t.Errorf("Did not get the expected error %s, got err = %v", tc.wantErrSubstring, err)
			}
		}
	}
}

func TestValidateAndUnpackCertWithIntermediatesSuccess(t *testing.T) {
	subject := "email@email"
	oidcIssuer := "https://accounts.google.com"

	rootCert, rootKey, _ := test.GenerateRootCa()
	subCert, subKey, _ := test.GenerateSubordinateCa(rootCert, rootKey)
	leafCert, _, _ := test.GenerateLeafCert(subject, oidcIssuer, subCert, subKey)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)
	subPool := x509.NewCertPool()
	rootPool.AddCert(subCert)

	co := &CheckOpts{
		RootCerts:  rootPool,
		IgnoreSCT:  true,
		Identities: []Identity{{Subject: subject, Issuer: oidcIssuer}},
	}

	_, err := ValidateAndUnpackCertWithIntermediates(leafCert, co, subPool)
	if err != nil {
		t.Errorf("ValidateAndUnpackCertWithIntermediates expected no error, got err = %v", err)
	}
	err = CheckCertificatePolicy(leafCert, co)
	if err != nil {
		t.Errorf("CheckCertificatePolicy expected no error, got err = %v", err)
	}
}

func TestValidateUnpackCertWithTrustedMaterial(t *testing.T) {
	subject := "email@email"
	oidcIssuer := "https://accounts.google.com"
	var ca root.FulcioCertificateAuthority
	rootCert, rootKey, _ := test.GenerateRootCa()
	ca.Root = rootCert
	leafCert, _, _ := test.GenerateLeafCert(subject, oidcIssuer, rootCert, rootKey)
	trustedRoot, err := root.NewTrustedRoot(root.TrustedRootMediaType01, []root.CertificateAuthority{&ca}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	co := &CheckOpts{
		TrustedMaterial: trustedRoot,
		IgnoreSCT:       true,
		Identities:      []Identity{{Subject: subject, Issuer: oidcIssuer}},
	}
	_, err = ValidateAndUnpackCert(leafCert, co)
	assert.NoError(t, err)
}

func TestValidateAndUnpackCertWithSCT(t *testing.T) {
	chain, err := cryptoutils.UnmarshalCertificatesFromPEM([]byte(strings.Join([]string{testEmbeddedCertPEM, testRootCertPEM}, "\n")))
	if err != nil {
		t.Fatalf("error unmarshalling certificate chain: %v", err)
	}

	rootPool := x509.NewCertPool()
	rootPool.AddCert(chain[1])

	// Grab the CTLog public keys
	pubKeys, err := GetCTLogPubs(context.Background())
	if err != nil {
		t.Fatalf("Failed to get CTLog public keys from TUF: %v", err)
	}

	co := &CheckOpts{
		RootCerts: rootPool,
		// explicitly set to false
		IgnoreSCT:    false,
		CTLogPubKeys: pubKeys,
	}

	// write SCT verification key to disk
	tmpPrivFile, err := os.CreateTemp(t.TempDir(), "cosign_verify_sct_*.key")
	if err != nil {
		t.Fatalf("failed to create temp key file: %v", err)
	}
	defer tmpPrivFile.Close()
	if _, err := tmpPrivFile.Write([]byte(testCTLogPublicKeyPEM)); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}
	t.Setenv("SIGSTORE_CT_LOG_PUBLIC_KEY_FILE", tmpPrivFile.Name())

	// Grab the CTLog public keys again so we get them from env.
	co.CTLogPubKeys, err = GetCTLogPubs(context.Background())
	if err != nil {
		t.Fatalf("Failed to get CTLog public keys from TUF: %v", err)
	}
	_, err = ValidateAndUnpackCert(chain[0], co)
	if err != nil {
		t.Errorf("ValidateAndUnpackCert expected no error, got err = %v", err)
	}

	// validate again, explicitly setting ignore SCT to false
	co.IgnoreSCT = false
	_, err = ValidateAndUnpackCert(chain[0], co)
	if err != nil {
		t.Errorf("ValidateAndUnpackCert expected no error, got err = %v", err)
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
	leafCert, _, _ := test.GenerateLeafCert("subject@mail.com", "oidc-issuer", subCert, subKey)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)
	subPool := x509.NewCertPool()
	subPool.AddCert(subCert)

	chains, err := TrustedCert(leafCert, rootPool, subPool)
	if err != nil {
		t.Fatalf("expected no error verifying certificate, got %v", err)
	}
	if len(chains) != 1 {
		t.Fatalf("unexpected number of chains found, expected 1, got %v", len(chains))
	}
	if len(chains[0]) != 3 {
		t.Fatalf("unexpected number of certs in chain, expected 3, got %v", len(chains[0]))
	}
}

func TestTrustedCertSuccessNoIntermediates(t *testing.T) {
	rootCert, rootKey, _ := test.GenerateRootCa()
	leafCert, _, _ := test.GenerateLeafCert("subject@mail.com", "oidc-issuer", rootCert, rootKey)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	_, err := TrustedCert(leafCert, rootPool, nil)
	if err != nil {
		t.Fatalf("expected no error verifying certificate, got %v", err)
	}
}

// Tests that verification succeeds if both a root and subordinate pool are
// present, but a chain is built with only the leaf and root certificates.
func TestTrustedCertSuccessChainFromRoot(t *testing.T) {
	rootCert, rootKey, _ := test.GenerateRootCa()
	leafCert, _, _ := test.GenerateLeafCert("subject@mail.com", "oidc-issuer", rootCert, rootKey)
	subCert, _, _ := test.GenerateSubordinateCa(rootCert, rootKey)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)
	subPool := x509.NewCertPool()
	subPool.AddCert(subCert)

	_, err := TrustedCert(leafCert, rootPool, subPool)
	if err != nil {
		t.Fatalf("expected no error verifying certificate, got %v", err)
	}
}

func TestVerifyRFC3161Timestamp(t *testing.T) {
	// generate signed artifact
	rootCert, rootKey, _ := test.GenerateRootCa()
	leafCert, privKey, _ := test.GenerateLeafCert("subject", "oidc-issuer", rootCert, rootKey)
	pemRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Raw})
	pemLeaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Raw})
	payload := []byte{1, 2, 3, 4}
	h := sha256.Sum256(payload)
	signature, _ := privKey.Sign(rand.Reader, h[:], crypto.SHA256)

	client, err := tsaMock.NewTSAClient((tsaMock.TSAClientOptions{Time: time.Now()}))
	if err != nil {
		t.Fatal(err)
	}

	tsBytes, err := tsa.GetTimestampedSignature(signature, client)
	if err != nil {
		t.Fatalf("unexpected error creating timestamp: %v", err)
	}
	rfc3161TS := bundle.RFC3161Timestamp{SignedRFC3161Timestamp: tsBytes}

	certChainPEM, err := cryptoutils.MarshalCertificatesToPEM(client.CertChain)
	if err != nil {
		t.Fatalf("unexpected error marshalling cert chain: %v", err)
	}

	leaves, intermediates, roots, err := tsa.SplitPEMCertificateChain(certChainPEM)
	if err != nil {
		t.Fatal("error splitting response into certificate chain")
	}

	ociSig, _ := static.NewSignature(payload,
		base64.StdEncoding.EncodeToString(signature),
		static.WithCertChain(pemLeaf, appendSlices([][]byte{pemRoot})),
		static.WithRFC3161Timestamp(&rfc3161TS))

	// success, signing over signature
	ts, err := VerifyRFC3161Timestamp(ociSig, &CheckOpts{
		TSACertificate:              leaves[0],
		TSAIntermediateCertificates: intermediates,
		TSARootCertificates:         roots,
	})
	if err != nil {
		t.Fatalf("unexpected error verifying timestamp with signature: %v", err)
	}
	if err := CheckExpiry(leafCert, ts.Time); err != nil {
		t.Fatalf("unexpected error using time from timestamp to verify certificate: %v", err)
	}

	// success, signing over payload
	tsBytes, err = tsa.GetTimestampedSignature(payload, client)
	if err != nil {
		t.Fatalf("unexpected error creating timestamp: %v", err)
	}
	rfc3161TS = bundle.RFC3161Timestamp{SignedRFC3161Timestamp: tsBytes}
	ociSig, _ = static.NewSignature(payload,
		"", /*signature*/
		static.WithCertChain(pemLeaf, appendSlices([][]byte{pemRoot})),
		static.WithRFC3161Timestamp(&rfc3161TS))
	_, err = VerifyRFC3161Timestamp(ociSig, &CheckOpts{
		TSACertificate:              leaves[0],
		TSAIntermediateCertificates: intermediates,
		TSARootCertificates:         roots,
	})
	if err != nil {
		t.Fatalf("unexpected error verifying timestamp with payload: %v", err)
	}

	// failure with non-base64 encoded signature
	ociSig, _ = static.NewSignature(payload,
		string(signature),
		static.WithCertChain(pemLeaf, appendSlices([][]byte{pemRoot})),
		static.WithRFC3161Timestamp(&rfc3161TS))
	_, err = VerifyRFC3161Timestamp(ociSig, &CheckOpts{
		TSACertificate:              leaves[0],
		TSAIntermediateCertificates: intermediates,
		TSARootCertificates:         roots,
	})
	if err == nil || !strings.Contains(err.Error(), "base64 data") {
		t.Fatalf("expected error verifying timestamp with raw signature, got: %v", err)
	}

	// failure with mismatched signature
	tsBytes, err = tsa.GetTimestampedSignature(signature, client)
	if err != nil {
		t.Fatalf("unexpected error creating timestamp: %v", err)
	}
	rfc3161TS = bundle.RFC3161Timestamp{SignedRFC3161Timestamp: tsBytes}
	// regenerate signature
	signature, _ = privKey.Sign(rand.Reader, h[:], crypto.SHA256)
	ociSig, _ = static.NewSignature(payload,
		base64.StdEncoding.EncodeToString(signature),
		static.WithCertChain(pemLeaf, appendSlices([][]byte{pemRoot})),
		static.WithRFC3161Timestamp(&rfc3161TS))
	_, err = VerifyRFC3161Timestamp(ociSig, &CheckOpts{
		TSACertificate:              leaves[0],
		TSAIntermediateCertificates: intermediates,
		TSARootCertificates:         roots,
	})
	if err == nil || !strings.Contains(err.Error(), "hashed messages don't match") {
		t.Fatalf("expected error verifying mismatched signatures, got: %v", err)
	}

	// failure without root certificate
	_, err = VerifyRFC3161Timestamp(ociSig, &CheckOpts{
		TSACertificate:              leaves[0],
		TSAIntermediateCertificates: intermediates,
	})
	if err == nil || !strings.Contains(err.Error(), "no TSA root certificate(s) provided to verify timestamp") {
		t.Fatalf("expected error verifying without a root certificate, got: %v", err)
	}
}

func TestVerifyImageAttestation(t *testing.T) {
	if _, _, err := VerifyImageAttestation(context.TODO(), nil, v1.Hash{}, nil); err == nil {
		t.Error("VerifyImageAttestation() should error when given nil attestations")
	}
}

// Mock Rekor client
type mockEntriesClient struct {
	entries.ClientService
	searchLogQueryFunc func(params *entries.SearchLogQueryParams, opts ...entries.ClientOption) (*entries.SearchLogQueryOK, error)
}

func (m *mockEntriesClient) SearchLogQuery(params *entries.SearchLogQueryParams, opts ...entries.ClientOption) (*entries.SearchLogQueryOK, error) {
	if m.searchLogQueryFunc != nil {
		return m.searchLogQueryFunc(params, opts...)
	}
	return nil, nil
}

// createRekorEntry creates a mock Rekor log entry.
func createRekorEntry(ctx context.Context, t *testing.T, logID string, signer signature.Signer, payload, signature []byte, publicKey crypto.PublicKey) *models.LogEntry {
	payloadHash := sha256.Sum256(payload)

	publicKeyBytes, err := cryptoutils.MarshalPublicKeyToPEM(publicKey)
	require.NoError(t, err)

	artifactProperties := rtypes.ArtifactProperties{
		ArtifactHash:   hex.EncodeToString(payloadHash[:]),
		SignatureBytes: signature,
		PublicKeyBytes: [][]byte{publicKeyBytes},
		PKIFormat:      "x509",
	}

	// Create and canonicalize Rekor entry
	entryProps, err := hashedrekord_v001.V001Entry{}.CreateFromArtifactProperties(ctx, artifactProperties)
	require.NoError(t, err)

	rekorEntry, err := rtypes.UnmarshalEntry(entryProps)
	require.NoError(t, err)

	canonicalEntry, err := rekorEntry.Canonicalize(ctx)
	require.NoError(t, err)

	// Create log entry
	integratedTime := time.Now().Unix()
	logEntry := models.LogEntryAnon{
		Body:           base64.StdEncoding.EncodeToString(canonicalEntry),
		IntegratedTime: conv.Pointer(integratedTime),
		LogIndex:       conv.Pointer(int64(0)),
		LogID:          conv.Pointer(logID),
	}

	// Canonicalize the log entry and sign it
	jsonLogEntry, err := json.Marshal(logEntry)
	require.NoError(t, err)

	canonicalPayload, err := jsoncanonicalizer.Transform(jsonLogEntry)
	require.NoError(t, err)

	signedEntryTimestamp, err := signer.SignMessage(bytes.NewReader(canonicalPayload))
	require.NoError(t, err)

	// Calculate leaf hash and add verification
	entryUUID, err := ComputeLeafHash(&logEntry)
	require.NoError(t, err)

	logEntry.Verification = &models.LogEntryAnonVerification{
		SignedEntryTimestamp: signedEntryTimestamp,
		InclusionProof: &models.InclusionProof{
			LogIndex: conv.Pointer(int64(0)),
			TreeSize: conv.Pointer(int64(1)),
			RootHash: conv.Pointer(hex.EncodeToString(entryUUID)),
			Hashes:   []string{},
		},
	}

	// Return the constructed log entry
	return &models.LogEntry{hex.EncodeToString(entryUUID): logEntry}
}

// generateSigner creates an ECDSA signer and public key.
func generateSigner(t *testing.T) (signature.SignerVerifier, crypto.PublicKey) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "error generating private key")

	signer, err := signature.LoadECDSASignerVerifier(privateKey, crypto.SHA256)
	require.NoError(t, err, "error loading signer")

	publicKey, err := signer.PublicKey()
	require.NoError(t, err, "error getting public key")

	return signer, publicKey
}

// generateBlobSignature signs a blob and returns the blob, its signature, and the base64-encoded signature.
func generateBlobSignature(t *testing.T, signer signature.Signer) ([]byte, []byte, string) {
	blob := []byte("foo")
	blobSignature, err := signer.SignMessage(bytes.NewReader(blob))
	require.NoError(t, err, "error signing blob")
	blobSignatureBase64 := base64.StdEncoding.EncodeToString(blobSignature)
	return blob, blobSignature, blobSignatureBase64
}

// calculateLogID generates a SHA-256 hash of the given public key and returns it as a hexadecimal string.
func calculateLogID(t *testing.T, pub crypto.PublicKey) string {
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err, "error marshalling public key")
	digest := sha256.Sum256(pubBytes)
	return hex.EncodeToString(digest[:])
}

func TestHasLocalBundles_V2Signatures(t *testing.T) {
	// Create a signed image with v2-style signatures (no bundle annotation)
	si := createSignedImageWithSignatures(t, false /* withBundle */)
	tmp := t.TempDir()
	if err := layout.WriteSignedImage(tmp, si); err != nil {
		t.Fatalf("WriteSignedImage() = %v", err)
	}

	hasBundles, err := HasLocalBundles(tmp)
	require.NoError(t, err)
	assert.False(t, hasBundles, "expected false for v2 signatures without bundles")
}

func TestHasLocalBundles_V3Bundles(t *testing.T) {
	// Create a layout with v3-style sigstore bundles
	tmp := createV3BundleLayout(t)

	hasBundles, err := HasLocalBundles(tmp)
	require.NoError(t, err)
	assert.True(t, hasBundles, "expected true for v3 signatures with bundles")
}

func TestHasLocalBundles_NoSignatures(t *testing.T) {
	// Create an image without any signatures
	img, err := random.Image(100, 3)
	require.NoError(t, err)
	si := signed.Image(img)
	tmp := t.TempDir()
	if err := layout.WriteSignedImage(tmp, si); err != nil {
		t.Fatalf("WriteSignedImage() = %v", err)
	}

	hasBundles, err := HasLocalBundles(tmp)
	require.NoError(t, err)
	assert.False(t, hasBundles, "expected false for image without signatures")
}

func TestHasLocalBundles_MixedFormats(t *testing.T) {
	// Create a layout with v3-style sigstore bundles (mixed = has bundles)
	tmp := createV3BundleLayout(t)

	hasBundles, err := HasLocalBundles(tmp)
	require.NoError(t, err)
	assert.True(t, hasBundles, "expected true when at least one v3 bundle exists")
}

func TestHasLocalBundles_InvalidPath(t *testing.T) {
	_, err := HasLocalBundles("/nonexistent/path")
	require.Error(t, err, "expected error for non-existent path")
}

// createSignedImageWithSignatures creates a test signed image with signatures.
// If withBundle is true, this creates a v3-style layout with sigstore bundle media type.
func createSignedImageWithSignatures(t *testing.T, withBundle bool) oci.SignedImage {
	return createTestSignedImage(t, withBundle, false)
}

func createSignedImageWithAttestations(t *testing.T, withBundle bool) oci.SignedImage {
	return createTestSignedImage(t, withBundle, true)
}

func createTestSignedImage(t *testing.T, withBundle, attestation bool) oci.SignedImage {
	t.Helper()
	img, err := random.Image(100, 3)
	require.NoError(t, err)
	si := signed.Image(img)

	// For v2-style signatures, attach them to the image
	if !withBundle {
		sig, err := static.NewSignature(nil, "test-payload")
		require.NoError(t, err)

		if attestation {
			si, err = mutate.AttachAttestationToImage(si, sig)
		} else {
			si, err = mutate.AttachSignatureToImage(si, sig)
		}
		require.NoError(t, err)
	}
	// For v3-style bundles, they need to be created separately with proper media type
	// The calling test should handle this differently

	return si
}

// createV3BundleLayout creates a layout directory with a v3 sigstore bundle.
// V3 bundles are stored as separate images with layers having the sigstore bundle media type.
func createV3BundleLayout(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()

	// Create a basic image
	img, err := random.Image(100, 3)
	require.NoError(t, err)
	si := signed.Image(img)

	// Write the signed image
	if err := layout.WriteSignedImage(tmp, si); err != nil {
		t.Fatalf("WriteSignedImage() = %v", err)
	}

	// Now manually append an image with a sigstore bundle layer
	p, err := ggcrlayout.FromPath(tmp)
	require.NoError(t, err)

	// Create a layer with the sigstore bundle media type
	bundleContent := []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`)
	bundleLayer := ggcrstatic.NewLayer(bundleContent, "application/vnd.dev.sigstore.bundle.v0.3+json")

	// Create an empty image and add the bundle layer
	emptyImg := empty.Image
	bundleImg, err := ggcrmutate.AppendLayers(emptyImg, bundleLayer)
	require.NoError(t, err)

	// Append the bundle image to the layout
	err = p.AppendImage(bundleImg)
	require.NoError(t, err)

	return tmp
}

func TestHasLocalAttestationBundles_V2Attestations(t *testing.T) {
	si := createSignedImageWithAttestations(t, false)
	tmp := t.TempDir()
	if err := layout.WriteSignedImage(tmp, si); err != nil {
		t.Fatalf("WriteSignedImage() = %v", err)
	}

	hasBundles, err := HasLocalAttestationBundles(tmp)
	require.NoError(t, err)
	assert.False(t, hasBundles, "expected false for v2 attestations without bundles")
}

func TestHasLocalAttestationBundles_V3Bundles(t *testing.T) {
	// V3 bundles are the same for signatures and attestations
	tmp := createV3BundleLayout(t)

	hasBundles, err := HasLocalAttestationBundles(tmp)
	require.NoError(t, err)
	assert.True(t, hasBundles, "expected true for v3 attestations with bundles")
}
