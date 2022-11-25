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
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/go-openapi/strfmt"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/internal/pkg/cosign/payload"
	"github.com/sigstore/cosign/internal/pkg/cosign/rekor/mock"
	"github.com/sigstore/cosign/internal/pkg/cosign/tsa"
	"github.com/sigstore/cosign/pkg/cosign/bundle"
	"github.com/sigstore/cosign/pkg/oci/static"
	"github.com/sigstore/cosign/pkg/types"
	"github.com/sigstore/cosign/test"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	rtypes "github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
	"github.com/sigstore/sigstore/pkg/tuf"
	tsaclient "github.com/sigstore/timestamp-authority/pkg/client"
	"github.com/sigstore/timestamp-authority/pkg/server"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"github.com/transparency-dev/merkle/rfc6962"
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
	verified, err := VerifyImageSignature(context.TODO(), ociSig, v1.Hash{}, &CheckOpts{RootCerts: rootPool, IgnoreSCT: true, SkipTlogVerify: true})
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
	verified, err := VerifyImageSignature(context.TODO(), ociSig, v1.Hash{}, &CheckOpts{RootCerts: rootPool, IgnoreSCT: true, SkipTlogVerify: true})
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
	keyID, _ := getLogID(pk)
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

func TestVerifyImageSignatureWithNoChain(t *testing.T) {
	ctx := context.Background()
	rootCert, rootKey, _ := test.GenerateRootCa()
	sv, _, err := signature.NewECDSASignerVerifier(elliptic.P256(), rand.Reader, crypto.SHA256)
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}

	leafCert, privKey, _ := test.GenerateLeafCert("subject", "oidc-issuer", rootCert, rootKey)
	pemLeaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Raw})

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	payload := []byte{1, 2, 3, 4}
	h := sha256.Sum256(payload)
	signature, _ := privKey.Sign(rand.Reader, h[:], crypto.SHA256)

	// Create a fake bundle
	pe, _ := proposedEntry(base64.StdEncoding.EncodeToString(signature), payload, pemLeaf)
	entry, _ := rtypes.UnmarshalEntry(pe[0])
	leaf, _ := entry.Canonicalize(ctx)
	rekorBundle := CreateTestBundle(ctx, t, sv, leaf)
	pemBytes, _ := cryptoutils.MarshalPublicKeyToPEM(sv.Public())
	rekorPubKeys := NewTrustedRekorPubKeys()
	rekorPubKeys.AddRekorPubKey(pemBytes, tuf.Active)

	opts := []static.Option{static.WithCertChain(pemLeaf, []byte{}), static.WithBundle(rekorBundle)}
	ociSig, _ := static.NewSignature(payload, base64.StdEncoding.EncodeToString(signature), opts...)

	verified, err := VerifyImageSignature(context.TODO(), ociSig, v1.Hash{},
		&CheckOpts{
			RootCerts:    rootPool,
			IgnoreSCT:    true,
			RekorPubKeys: &rekorPubKeys})
	if err != nil {
		t.Fatalf("unexpected error %v", err)
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
	verified, err := VerifyImageSignature(context.TODO(), ociSig, v1.Hash{}, &CheckOpts{RootCerts: rootPool, IgnoreSCT: true, SkipTlogVerify: true})
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
	verified, err := VerifyImageSignature(context.TODO(), ociSig, v1.Hash{}, &CheckOpts{RootCerts: rootPool, IgnoreSCT: true, SkipTlogVerify: true})
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
	leafCert, privKey, _ := test.GenerateLeafCert("subject", "oidc-issuer", subCert, subKey)
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
	verified, err := VerifyImageSignature(context.TODO(), ociSig, v1.Hash{}, &CheckOpts{RootCerts: rootPool, UntrustedIntermediateCerts: subPool, IgnoreSCT: true, SkipTlogVerify: true})
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

// This test ensures that image signature validation fails properly if we are
// using a SigVerifier with Rekor.
// In other words, we require checking against RekorPubKeys when verifying
// image signature.
// This could be made more robust with supplying a mismatched trusted RekorPubKeys
// rather than none.
// See https://github.com/sigstore/cosign/issues/1816 for more details.
func TestVerifyImageSignatureWithSigVerifierAndRekor(t *testing.T) {
	sv, privKey, err := signature.NewDefaultECDSASignerVerifier()
	if err != nil {
		t.Fatalf("error generating verifier: %v", err)
	}

	payload := []byte{1, 2, 3, 4}
	h := sha256.Sum256(payload)
	sig, _ := privKey.Sign(rand.Reader, h[:], crypto.SHA256)
	ociSig, _ := static.NewSignature(payload, base64.StdEncoding.EncodeToString(sig))

	// Add a fake rekor client - this makes it look like there's a matching
	// tlog entry for the signature during validation (even though it does not
	// match the underlying data / key)
	mClient := new(client.Rekor)
	mClient.Entries = &mock.EntriesClient{
		Entries: []*models.LogEntry{&data},
	}

	if _, err := VerifyImageSignature(context.TODO(), ociSig, v1.Hash{}, &CheckOpts{
		SigVerifier: sv,
		RekorClient: mClient,
	}); err == nil || !strings.Contains(err.Error(), "no valid tlog entries found no trusted rekor public keys provided") {
		// This is failing to validate the Rekor public key itself.
		// At the very least this ensures
		// that we're hitting tlog validation during signature checking.
		t.Fatalf("expected error while verifying signature, got %s", err)
	}
}

func TestVerifyImageSignatureWithSigVerifierAndTSA(t *testing.T) {
	// TODO: Replace with a full TSA mock client, related to https://github.com/sigstore/timestamp-authority/issues/146
	viper.Set("timestamp-signer", "memory")
	apiServer := server.NewRestAPIServer("localhost", 0, []string{"http"}, 10*time.Second, 10*time.Second)
	server := httptest.NewServer(apiServer.GetHandler())
	t.Cleanup(server.Close)

	client, err := tsaclient.GetTimestampClient(server.URL)
	if err != nil {
		t.Error(err)
	}
	sv, _, err := signature.NewDefaultECDSASignerVerifier()
	if err != nil {
		t.Fatalf("error generating verifier: %v", err)
	}
	payloadSigner := payload.NewSigner(sv)
	testSigner := tsa.NewSigner(payloadSigner, client)

	chain, err := client.Timestamp.GetTimestampCertChain(nil)
	if err != nil {
		t.Fatalf("unexpected error getting timestamp chain: %v", err)
	}

	tsaCertPool := x509.NewCertPool()
	ok := tsaCertPool.AppendCertsFromPEM([]byte(chain.Payload))
	if !ok {
		t.Fatal("error parsing response into Timestamp while appending certs from PEM")
	}

	payload := []byte{1, 2, 3, 4}
	sig, _, err := testSigner.Sign(context.Background(), bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("error signing the payload with the tsa client server: %v", err)
	}
	if bundleVerified, err := VerifyImageSignature(context.TODO(), sig, v1.Hash{}, &CheckOpts{
		SigVerifier:    sv,
		TSACerts:       tsaCertPool,
		SkipTlogVerify: true,
	}); err != nil || bundleVerified { // bundle is not verified since there's no Rekor bundle
		t.Fatalf("unexpected error while verifying signature, got %v", err)
	}
}

func TestVerifyImageSignatureWithSigVerifierAndRekorTSA(t *testing.T) {
	// TODO: Replace with a full TSA mock client, related to https://github.com/sigstore/timestamp-authority/issues/146
	viper.Set("timestamp-signer", "memory")
	apiServer := server.NewRestAPIServer("localhost", 0, []string{"http"}, 10*time.Second, 10*time.Second)
	server := httptest.NewServer(apiServer.GetHandler())
	t.Cleanup(server.Close)

	// Add a fake rekor client - this makes it look like there's a matching
	// tlog entry for the signature during validation (even though it does not
	// match the underlying data / key)
	mClient := new(client.Rekor)
	mClient.Entries = &mock.EntriesClient{
		Entries: []*models.LogEntry{&data},
	}

	client, err := tsaclient.GetTimestampClient(server.URL)
	if err != nil {
		t.Error(err)
	}
	sv, _, err := signature.NewDefaultECDSASignerVerifier()
	if err != nil {
		t.Fatalf("error generating verifier: %v", err)
	}
	payloadSigner := payload.NewSigner(sv)
	tsaSigner := tsa.NewSigner(payloadSigner, client)

	chain, err := client.Timestamp.GetTimestampCertChain(nil)
	if err != nil {
		t.Fatalf("unexpected error getting timestamp chain: %v", err)
	}

	tsaCertPool := x509.NewCertPool()
	ok := tsaCertPool.AppendCertsFromPEM([]byte(chain.Payload))
	if !ok {
		t.Fatal("error parsing response into Timestamp while appending certs from PEM")
	}

	payload := []byte{1, 2, 3, 4}
	sig, _, err := tsaSigner.Sign(context.Background(), bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("error signing the payload with the rekor and tsa clients: %v", err)
	}
	if _, err := VerifyImageSignature(context.TODO(), sig, v1.Hash{}, &CheckOpts{
		SigVerifier: sv,
		TSACerts:    tsaCertPool,
		RekorClient: mClient,
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
		IgnoreSCT:      true,
	}

	_, err := ValidateAndUnpackCert(leafCert, co)
	if err != nil {
		t.Errorf("ValidateAndUnpackCert expected no error, got err = %v", err)
	}
	err = CheckCertificateIssuerAndSubject(leafCert, co)
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
		RootCerts: rootPool,
		IgnoreSCT: true,
	}

	_, err := ValidateAndUnpackCert(leafCert, co)
	if err != nil {
		t.Errorf("ValidateAndUnpackCert expected no error, got err = %v", err)
	}
	err = CheckCertificateIssuerAndSubject(leafCert, co)
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
		RootCerts:      rootPool,
		CertEmail:      subject,
		CertOidcIssuer: oidcIssuer,
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
		RootCerts:      rootPool,
		CertIdentity:   subject,
		CertOidcIssuer: oidcIssuer,
		IgnoreSCT:      true,
	}

	_, err := ValidateAndUnpackCert(leafCert, co)
	if err != nil {
		t.Errorf("ValidateAndUnpackCert expected no error, got err = %v", err)
	}
	err = CheckCertificateIssuerAndSubject(leafCert, co)
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
		RootCerts:      rootPool,
		CertIdentity:   subject,
		CertOidcIssuer: oidcIssuer,
		IgnoreSCT:      true,
	}

	_, err := ValidateAndUnpackCert(leafCert, co)
	if err != nil {
		t.Errorf("ValidateAndUnpackCert expected no error, got err = %v", err)
	}
	err = CheckCertificateIssuerAndSubject(leafCert, co)
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
		RootCerts:      rootPool,
		CertIdentity:   subject,
		CertOidcIssuer: oidcIssuer,
		IgnoreSCT:      true,
	}

	_, err := ValidateAndUnpackCert(leafCert, co)
	if err != nil {
		t.Errorf("ValidateAndUnpackCert expected no error, got err = %v", err)
	}
	err = CheckCertificateIssuerAndSubject(leafCert, co)
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
		RootCerts:      rootPool,
		CertIdentity:   "scheme://userinfo@host",
		CertOidcIssuer: oidcIssuer,
		IgnoreSCT:      true,
	}

	_, err := ValidateAndUnpackCert(leafCert, co)
	if err != nil {
		t.Errorf("ValidateAndUnpackCert expected no error, got err = %v", err)
	}
	err = CheckCertificateIssuerAndSubject(leafCert, co)
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
		RootCerts:      rootPool,
		CertIdentity:   subject,
		CertOidcIssuer: oidcIssuer,
		IgnoreSCT:      true,
	}

	_, err = ValidateAndUnpackCert(leafCert, co)
	if err != nil {
		t.Errorf("ValidateAndUnpackCert expected no error, got err = %v", err)
	}
	err = CheckCertificateIssuerAndSubject(leafCert, co)
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
		RootCerts:      rootPool,
		CertEmail:      subject,
		CertOidcIssuer: oidcIssuer,
		IgnoreSCT:      true,
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
		IgnoreSCT:      true,
	}

	_, err := ValidateAndUnpackCert(leafCert, co)
	require.Contains(t, err.Error(), "expected oidc issuer not found in certificate")
	err = CheckCertificateIssuerAndSubject(leafCert, co)
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
		IgnoreSCT:      true,
	}

	_, err := ValidateAndUnpackCert(leafCert, co)
	require.Contains(t, err.Error(), "expected identity not found in certificate")
	err = CheckCertificateIssuerAndSubject(leafCert, co)
	require.Contains(t, err.Error(), "expected identity not found in certificate")
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
		CertEmail:                 subject,
		CertGithubWorkflowTrigger: "otherTrigger",
		CertOidcIssuer:            oidcIssuer,
		IgnoreSCT:                 true,
	}

	_, err := ValidateAndUnpackCert(leafCert, co)
	require.Contains(t, err.Error(), "expected GitHub Workflow Trigger not found in certificate")
	err = CheckCertificateIssuerAndSubject(leafCert, co)
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
		CertEmail:             subject,
		CertGithubWorkflowSha: "otherSHA",
		CertOidcIssuer:        oidcIssuer,
		IgnoreSCT:             true,
	}

	_, err := ValidateAndUnpackCert(leafCert, co)
	require.Contains(t, err.Error(), "expected GitHub Workflow SHA not found in certificate")
	err = CheckCertificateIssuerAndSubject(leafCert, co)
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
		CertEmail:              subject,
		CertGithubWorkflowName: "otherName",
		CertOidcIssuer:         oidcIssuer,
		IgnoreSCT:              true,
	}

	_, err := ValidateAndUnpackCert(leafCert, co)
	require.Contains(t, err.Error(), "expected GitHub Workflow Name not found in certificate")
	err = CheckCertificateIssuerAndSubject(leafCert, co)
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
		CertEmail:                    subject,
		CertGithubWorkflowRepository: "otherRepository",
		CertOidcIssuer:               oidcIssuer,
		IgnoreSCT:                    true,
	}

	_, err := ValidateAndUnpackCert(leafCert, co)
	require.Contains(t, err.Error(), "expected GitHub Workflow Repository not found in certificate")
	err = CheckCertificateIssuerAndSubject(leafCert, co)
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
		CertEmail:             subject,
		CertGithubWorkflowRef: "otherRef",
		CertOidcIssuer:        oidcIssuer,
		IgnoreSCT:             true,
	}

	_, err := ValidateAndUnpackCert(leafCert, co)
	require.Contains(t, err.Error(), "expected GitHub Workflow Ref not found in certificate")
	err = CheckCertificateIssuerAndSubject(leafCert, co)
	require.Contains(t, err.Error(), "expected GitHub Workflow Ref not found in certificate")
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
		IgnoreSCT:      true,
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
		IgnoreSCT:      true,
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
		IgnoreSCT:      true,
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
		IgnoreSCT:      true,
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
		err = CheckCertificateIssuerAndSubject(leafCert, co)
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

func TestCertificateSignedByTrustedRootSuccess(t *testing.T) {
	rootCert, rootKey, _ := test.GenerateRootCa()
	subCert, subKey, _ := test.GenerateSubordinateCa(rootCert, rootKey)
	leafCert, _, _ := test.GenerateLeafCert("subject", "oidc-issuer", subCert, subKey)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)
	subPool := x509.NewCertPool()
	subPool.AddCert(subCert)

	chains, err := CertificateSignedByTrustedRoot(leafCert, rootPool, subPool)
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

func TestCertificateSignedByTrustedRootSuccessNoIntermediates(t *testing.T) {
	rootCert, rootKey, _ := test.GenerateRootCa()
	leafCert, _, _ := test.GenerateLeafCert("subject", "oidc-issuer", rootCert, rootKey)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	_, err := CertificateSignedByTrustedRoot(leafCert, rootPool, nil)
	if err != nil {
		t.Fatalf("expected no error verifying certificate, got %v", err)
	}
}

// Tests that verification succeeds if both a root and subordinate pool are
// present, but a chain is built with only the leaf and root certificates.
func TestCertificateSignedByTrustedRootSuccessChainFromRoot(t *testing.T) {
	rootCert, rootKey, _ := test.GenerateRootCa()
	leafCert, _, _ := test.GenerateLeafCert("subject", "oidc-issuer", rootCert, rootKey)
	subCert, _, _ := test.GenerateSubordinateCa(rootCert, rootKey)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)
	subPool := x509.NewCertPool()
	subPool.AddCert(subCert)

	_, err := CertificateSignedByTrustedRoot(leafCert, rootPool, subPool)
	if err != nil {
		t.Fatalf("expected no error verifying certificate, got %v", err)
	}
}

func Test_getSubjectAltnernativeNames(t *testing.T) {
	rootCert, rootKey, _ := test.GenerateRootCa()
	subCert, subKey, _ := test.GenerateSubordinateCa(rootCert, rootKey)

	// generate with OtherName, which will override other SANs
	ext, err := cryptoutils.MarshalOtherNameSAN("subject-othername", true)
	if err != nil {
		t.Fatalf("error marshalling SANs: %v", err)
	}
	exts := []pkix.Extension{*ext}
	leafCert, _, _ := test.GenerateLeafCert("unused", "oidc-issuer", subCert, subKey, exts...)

	sans := getSubjectAlternateNames(leafCert)
	if len(sans) != 1 {
		t.Fatalf("expected 1 SAN field, got %d", len(sans))
	}
	if sans[0] != "subject-othername" {
		t.Fatalf("unexpected OtherName SAN value")
	}

	// generate with all other SANs
	leafCert, _, _ = test.GenerateLeafCertWithSubjectAlternateNames([]string{"subject-dns"}, []string{"subject-email"}, []net.IP{{1, 2, 3, 4}}, []*url.URL{{Path: "testURL"}}, "oidc-issuer", subCert, subKey)
	sans = getSubjectAlternateNames(leafCert)
	if len(sans) != 4 {
		t.Fatalf("expected 1 SAN field, got %d", len(sans))
	}
	if sans[0] != "subject-dns" {
		t.Fatalf("unexpected DNS SAN value")
	}
	if sans[1] != "subject-email" {
		t.Fatalf("unexpected email SAN value")
	}
	if sans[2] != "1.2.3.4" {
		t.Fatalf("unexpected IP SAN value")
	}
	if sans[3] != "testURL" {
		t.Fatalf("unexpected URL SAN value")
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

	// TODO: Replace with a TSA mock client, blocked by https://github.com/sigstore/timestamp-authority/issues/146
	viper.Set("timestamp-signer", "memory")
	apiServer := server.NewRestAPIServer("localhost", 0, []string{"http"}, 10*time.Second, 10*time.Second)
	server := httptest.NewServer(apiServer.GetHandler())
	t.Cleanup(server.Close)
	client, err := tsaclient.GetTimestampClient(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	tsBytes, err := tsa.GetTimestampedSignature(signature, client)
	if err != nil {
		t.Fatalf("unexpected error creating timestamp: %v", err)
	}
	rfc3161TS := bundle.RFC3161Timestamp{SignedRFC3161Timestamp: tsBytes}
	chain, err := client.Timestamp.GetTimestampCertChain(nil)
	if err != nil {
		t.Fatalf("unexpected error getting timestamp chain: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(chain.Payload)) {
		t.Fatalf("error creating trust root pool")
	}

	ociSig, _ := static.NewSignature(payload,
		base64.StdEncoding.EncodeToString(signature),
		static.WithCertChain(pemLeaf, appendSlices([][]byte{pemRoot})),
		static.WithRFC3161Timestamp(&rfc3161TS))

	// success, signing over signature
	ts, err := VerifyRFC3161Timestamp(ociSig, pool)
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
	_, err = VerifyRFC3161Timestamp(ociSig, pool)
	if err != nil {
		t.Fatalf("unexpected error verifying timestamp with payload: %v", err)
	}

	// failure with non-base64 encoded signature
	ociSig, _ = static.NewSignature(payload,
		string(signature),
		static.WithCertChain(pemLeaf, appendSlices([][]byte{pemRoot})),
		static.WithRFC3161Timestamp(&rfc3161TS))
	_, err = VerifyRFC3161Timestamp(ociSig, pool)
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
	_, err = VerifyRFC3161Timestamp(ociSig, pool)
	if err == nil || !strings.Contains(err.Error(), "hashed messages don't match") {
		t.Fatalf("expected error verifying mismatched signatures, got: %v", err)
	}
}
