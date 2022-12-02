// Copyright 2022 The Sigstore Authors.
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

package verify

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/swag"
	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/internal/pkg/cosign/payload"
	"github.com/sigstore/cosign/internal/pkg/cosign/tsa"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/bundle"
	"github.com/sigstore/cosign/pkg/oci"
	sigs "github.com/sigstore/cosign/pkg/signature"
	ctypes "github.com/sigstore/cosign/pkg/types"
	"github.com/sigstore/cosign/test"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/pki"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/types/hashedrekord"
	hashedrekord_v001 "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	"github.com/sigstore/rekor/pkg/types/intoto"
	"github.com/sigstore/rekor/pkg/types/rekord"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
	tsaclient "github.com/sigstore/timestamp-authority/pkg/client"
	"github.com/sigstore/timestamp-authority/pkg/server"
	"github.com/spf13/viper"
)

func TestSignaturesRef(t *testing.T) {
	sig := "a=="
	b64sig := "YT09"
	tests := []struct {
		description string
		sigRef      string
		shouldErr   bool
	}{
		{
			description: "raw sig",
			sigRef:      sig,
		},
		{
			description: "encoded sig",
			sigRef:      b64sig,
		}, {
			description: "empty ref",
			shouldErr:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			gotSig, err := base64signature(test.sigRef, "", "")
			if test.shouldErr && err != nil {
				return
			}
			if test.shouldErr {
				t.Fatal("should have received an error")
			}
			if gotSig != b64sig {
				t.Fatalf("unexpected signature, expected: %s got: %s", sig, gotSig)
			}
		})
	}
}

func TestSignaturesBundle(t *testing.T) {
	td := t.TempDir()
	fp := filepath.Join(td, "file")

	b64sig := "YT09"

	// save as a LocalSignedPayload to the file
	lsp := cosign.LocalSignedPayload{
		Base64Signature: b64sig,
	}
	contents, err := json.Marshal(lsp)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fp, contents, 0644); err != nil {
		t.Fatal(err)
	}

	gotSig, err := base64signature("", fp, "")
	if err != nil {
		t.Fatal(err)
	}
	if gotSig != b64sig {
		t.Fatalf("unexpected signature, expected: %s got: %s", b64sig, gotSig)
	}
}

func TestSignaturesRFC3161TimestampBundle(t *testing.T) {
	td := t.TempDir()
	fp := filepath.Join(td, "file")

	b64sig := "YT09"

	// save as a LocalSignedPayload to the file
	lsp := cosign.LocalSignedPayload{
		Base64Signature: b64sig,
	}
	contents, err := json.Marshal(lsp)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fp, contents, 0644); err != nil {
		t.Fatal(err)
	}

	gotSig, err := base64signature("", "", fp)
	if err != nil {
		t.Fatal(err)
	}
	if gotSig != b64sig {
		t.Fatalf("unexpected signature, expected: %s got: %s", b64sig, gotSig)
	}
}

func TestIsIntotoDSSEWithEnvelopes(t *testing.T) {
	tts := []struct {
		envelope     ssldsse.Envelope
		isIntotoDSSE bool
	}{
		{
			envelope: ssldsse.Envelope{
				PayloadType: "application/vnd.in-toto+json",
				Payload:     base64.StdEncoding.EncodeToString([]byte("This is a test")),
				Signatures:  []ssldsse.Signature{},
			},
			isIntotoDSSE: true,
		},
	}
	for _, tt := range tts {
		envlopeBytes, _ := json.Marshal(tt.envelope)
		got := isIntotoDSSE(envlopeBytes)
		if got != tt.isIntotoDSSE {
			t.Fatalf("unexpected envelope content")
		}
	}
}

func TestIsIntotoDSSEWithBytes(t *testing.T) {
	tts := []struct {
		envelope     []byte
		isIntotoDSSE bool
	}{
		{
			envelope:     []byte("This is no valid"),
			isIntotoDSSE: false,
		},
		{
			envelope:     []byte("MEUCIQDBmE1ZRFjUVic1hzukesJlmMFG1JqWWhcthnhawTeBNQIga3J9/WKsNlSZaySnl8V360bc2S8dIln2/qo186EfjHA="),
			isIntotoDSSE: false,
		},
	}
	for _, tt := range tts {
		envlopeBytes, _ := json.Marshal(tt.envelope)
		got := isIntotoDSSE(envlopeBytes)
		if got != tt.isIntotoDSSE {
			t.Fatalf("unexpected envelope content")
		}
	}
}

// Does not test identity options, only blob verification with different
// options.
func TestVerifyBlob(t *testing.T) {
	ctx := context.Background()
	td := t.TempDir()

	leafPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := signature.LoadECDSASignerVerifier(leafPriv, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	pubKeyBytes, err := sigs.PublicKeyPem(signer, signatureoptions.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}

	// Generate expired and unexpired certificates
	identity := "hello@foo.com"
	issuer := "issuer"
	rootCert, rootPriv, _ := test.GenerateRootCa()
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)
	chain, _ := cryptoutils.MarshalCertificatesToPEM([]*x509.Certificate{rootCert})
	chainPath := writeBlobFile(t, td, string(chain), "chain.pem")

	unexpiredLeafCert, _ := test.GenerateLeafCertWithExpiration(identity, issuer,
		time.Now(), leafPriv, rootCert, rootPriv)
	unexpiredCertPem, _ := cryptoutils.MarshalCertificateToPEM(unexpiredLeafCert)

	expiredLeafCert, _ := test.GenerateLeafCertWithExpiration(identity, issuer,
		time.Now().Add(-time.Hour), leafPriv, rootCert, rootPriv)
	expiredLeafPem, _ := cryptoutils.MarshalCertificateToPEM(expiredLeafCert)

	// Make rekor signer
	rekorPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rekorSigner, err := signature.LoadECDSASignerVerifier(rekorPriv, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	pemRekor, err := cryptoutils.MarshalPublicKeyToPEM(rekorSigner.Public())
	if err != nil {
		t.Fatal(err)
	}
	tmpRekorPubFile := writeBlobFile(t, td, string(pemRekor), "rekor_pub.key")
	t.Setenv("SIGSTORE_REKOR_PUBLIC_KEY", tmpRekorPubFile)

	var makeSignature = func(blob []byte) string {
		sig, err := signer.SignMessage(bytes.NewReader(blob))
		if err != nil {
			t.Fatal(err)
		}
		return string(sig)
	}
	blobBytes := []byte("foo")
	blobSignature := makeSignature(blobBytes)

	otherBytes := []byte("bar")
	otherSignature := makeSignature(otherBytes)

	tts := []struct {
		name       string
		blob       []byte
		signature  string
		key        []byte
		cert       *x509.Certificate
		bundlePath string
		// If online lookups to Rekor are enabled
		experimental bool
		// The rekor entry response when Rekor is enabled
		rekorEntry     []*models.LogEntry
		skipTlogVerify bool
		shouldErr      bool
	}{
		{
			name:           "valid signature with public key",
			blob:           blobBytes,
			signature:      blobSignature,
			key:            pubKeyBytes,
			experimental:   false,
			shouldErr:      false,
			skipTlogVerify: true,
		},
		/* TODO:
		This currently passes without error because we don't require an experimental
		lookup for public keys. Add this test back in when we have a --verify-tlog-online
		{
			name:         "valid signature with public key - experimental no rekor fail",
			blob:         blobBytes,
			signature:    blobSignature,
			key:          pubKeyBytes,
			experimental: true,
			rekorEntry:   nil,
			shouldErr:    true,
		},
		*/
		{
			name:         "valid signature with public key - experimental rekor entry success",
			blob:         blobBytes,
			signature:    blobSignature,
			key:          pubKeyBytes,
			experimental: true,
			rekorEntry: []*models.LogEntry{makeRekorEntry(t, *rekorSigner, blobBytes, []byte(blobSignature),
				pubKeyBytes, true)},
			shouldErr: false,
		},
		{
			name:         "valid signature with public key - good bundle provided",
			blob:         blobBytes,
			signature:    blobSignature,
			key:          pubKeyBytes,
			experimental: false,
			bundlePath: makeLocalBundle(t, *rekorSigner, blobBytes, []byte(blobSignature),
				pubKeyBytes, true),
			shouldErr: false,
		},
		{
			name:         "valid signature with public key - bundle without rekor bundle fails",
			blob:         blobBytes,
			signature:    blobSignature,
			key:          pubKeyBytes,
			experimental: false,
			bundlePath:   makeLocalBundleWithoutRekorBundle(t, []byte(blobSignature), pubKeyBytes),
			shouldErr:    true,
		},
		{
			name:         "valid signature with public key - bad bundle SET",
			blob:         blobBytes,
			signature:    blobSignature,
			key:          pubKeyBytes,
			experimental: false,
			bundlePath: makeLocalBundle(t, *signer, blobBytes, []byte(blobSignature),
				unexpiredCertPem, true),
			shouldErr: true,
		},
		{
			name:         "valid signature with public key - bad bundle cert mismatch",
			blob:         blobBytes,
			signature:    blobSignature,
			key:          pubKeyBytes,
			experimental: false,
			bundlePath: makeLocalBundle(t, *rekorSigner, blobBytes, []byte(blobSignature),
				unexpiredCertPem, true),
			shouldErr: true,
		},
		{
			name:         "valid signature with public key - bad bundle signature mismatch",
			blob:         blobBytes,
			signature:    blobSignature,
			key:          pubKeyBytes,
			experimental: false,
			bundlePath: makeLocalBundle(t, *rekorSigner, blobBytes, []byte(makeSignature(blobBytes)),
				pubKeyBytes, true),
			shouldErr: true,
		},
		{
			name:         "valid signature with public key - bad bundle msg & signature mismatch",
			blob:         blobBytes,
			signature:    blobSignature,
			key:          pubKeyBytes,
			experimental: false,
			bundlePath: makeLocalBundle(t, *rekorSigner, otherBytes, []byte(otherSignature),
				pubKeyBytes, true),
			shouldErr: true,
		},
		{
			name:         "invalid signature with public key",
			blob:         blobBytes,
			signature:    otherSignature,
			key:          pubKeyBytes,
			experimental: false,
			shouldErr:    true,
		},
		{
			name:         "invalid signature with public key - experimental",
			blob:         blobBytes,
			signature:    otherSignature,
			key:          pubKeyBytes,
			experimental: true,
			shouldErr:    true,
		},
		{
			name:         "valid signature with unexpired certificate - no rekor entry",
			blob:         blobBytes,
			signature:    blobSignature,
			cert:         unexpiredLeafCert,
			experimental: false,
			shouldErr:    true,
		},
		{
			name:         "valid signature with unexpired certificate - bad bundle cert mismatch",
			blob:         blobBytes,
			signature:    blobSignature,
			experimental: false,
			key:          pubKeyBytes,
			bundlePath: makeLocalBundle(t, *rekorSigner, blobBytes, []byte(blobSignature),
				unexpiredCertPem, true),
			shouldErr: true,
		},
		{
			name:         "valid signature with unexpired certificate - bad bundle signature mismatch",
			blob:         blobBytes,
			signature:    blobSignature,
			experimental: false,
			cert:         unexpiredLeafCert,
			bundlePath: makeLocalBundle(t, *rekorSigner, blobBytes, []byte(makeSignature(blobBytes)),
				unexpiredCertPem, true),
			shouldErr: true,
		},
		{
			name:         "valid signature with unexpired certificate - bad bundle msg & signature mismatch",
			blob:         blobBytes,
			signature:    blobSignature,
			experimental: false,
			cert:         unexpiredLeafCert,
			bundlePath: makeLocalBundle(t, *rekorSigner, otherBytes, []byte(otherSignature),
				unexpiredCertPem, true),
			shouldErr: true,
		},
		{
			name:         "invalid signature with unexpired certificate",
			blob:         blobBytes,
			signature:    otherSignature,
			cert:         unexpiredLeafCert,
			experimental: false,
			shouldErr:    true,
		},
		{
			name:         "valid signature with unexpired certificate - experimental",
			blob:         blobBytes,
			signature:    blobSignature,
			cert:         unexpiredLeafCert,
			experimental: true,
			rekorEntry: []*models.LogEntry{makeRekorEntry(t, *rekorSigner, blobBytes, []byte(blobSignature),
				unexpiredCertPem, true)},
			shouldErr: false,
		},
		{
			name:         "valid signature with unexpired certificate - experimental & rekor entry found",
			blob:         blobBytes,
			signature:    blobSignature,
			cert:         unexpiredLeafCert,
			experimental: true,
			rekorEntry: []*models.LogEntry{makeRekorEntry(t, *rekorSigner, blobBytes, []byte(blobSignature),
				unexpiredCertPem, true)},
			shouldErr: false,
		},
		{
			name:         "valid signature with expired certificate",
			blob:         blobBytes,
			signature:    blobSignature,
			cert:         expiredLeafCert,
			experimental: false,
			shouldErr:    true,
		},
		{
			name:         "valid signature with expired certificate - experimental good rekor lookup",
			blob:         blobBytes,
			signature:    blobSignature,
			cert:         expiredLeafCert,
			experimental: true,
			rekorEntry: []*models.LogEntry{makeRekorEntry(t, *rekorSigner, blobBytes, []byte(blobSignature),
				expiredLeafPem, true)},
			shouldErr: false,
		},
		{
			name:         "valid signature with expired certificate - experimental multiple rekor entries",
			blob:         blobBytes,
			signature:    blobSignature,
			cert:         expiredLeafCert,
			experimental: true,
			rekorEntry: []*models.LogEntry{makeRekorEntry(t, *rekorSigner, blobBytes, []byte(blobSignature),
				expiredLeafPem, true), makeRekorEntry(t, *rekorSigner, blobBytes, []byte(blobSignature),
				expiredLeafPem, false)},
			shouldErr: false,
		},
		{
			name:         "valid signature with expired certificate - experimental bad rekor integrated time",
			blob:         blobBytes,
			signature:    blobSignature,
			cert:         expiredLeafCert,
			experimental: true,
			rekorEntry: []*models.LogEntry{makeRekorEntry(t, *rekorSigner, blobBytes, []byte(blobSignature),
				expiredLeafPem, false)},
			shouldErr: true,
		},

		{
			name:         "valid signature with unexpired certificate - good bundle, nonexperimental",
			blob:         blobBytes,
			signature:    blobSignature,
			cert:         unexpiredLeafCert,
			experimental: false,
			bundlePath: makeLocalBundle(t, *rekorSigner, blobBytes, []byte(blobSignature),
				unexpiredCertPem, true),
			shouldErr: false,
		},
		{
			name:         "valid signature with expired certificate - good bundle, nonexperimental",
			blob:         blobBytes,
			signature:    blobSignature,
			cert:         expiredLeafCert,
			experimental: false,
			bundlePath: makeLocalBundle(t, *rekorSigner, blobBytes, []byte(blobSignature),
				expiredLeafPem, true),
			shouldErr: false,
		},
		{
			name:         "valid signature with expired certificate - bundle with bad expiration",
			blob:         blobBytes,
			signature:    blobSignature,
			cert:         expiredLeafCert,
			experimental: false,
			bundlePath: makeLocalBundle(t, *rekorSigner, blobBytes, []byte(blobSignature),
				expiredLeafPem, false),
			shouldErr: true,
		},
		{
			name:         "valid signature with expired certificate - bundle with bad SET",
			blob:         blobBytes,
			signature:    blobSignature,
			cert:         expiredLeafCert,
			experimental: false,
			bundlePath: makeLocalBundle(t, *signer, blobBytes, []byte(blobSignature),
				expiredLeafPem, true),
			shouldErr: true,
		},
		{
			name:         "valid signature with expired certificate - experimental good bundle",
			blob:         blobBytes,
			signature:    blobSignature,
			cert:         expiredLeafCert,
			experimental: true,
			bundlePath: makeLocalBundle(t, *rekorSigner, blobBytes, []byte(blobSignature),
				expiredLeafPem, true),
			shouldErr: false,
		},
		{
			name:         "valid signature with expired certificate - experimental bad rekor entry",
			blob:         blobBytes,
			signature:    blobSignature,
			cert:         expiredLeafCert,
			experimental: true,
			// This is the wrong signer for the SET!
			rekorEntry: []*models.LogEntry{makeRekorEntry(t, *signer, blobBytes, []byte(blobSignature),
				expiredLeafPem, true)},
			shouldErr: true,
		},
	}
	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt
			entries := make([]models.LogEntry, 0)
			for _, entry := range tt.rekorEntry {
				entries = append(entries, *entry)
			}
			testServer := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(entries)
				}))
			defer testServer.Close()

			// Verify command
			cmd := VerifyBlobCmd{
				KeyOpts: options.KeyOpts{
					BundlePath: tt.bundlePath,
					RekorURL:   testServer.URL},
				CertEmail:      identity,
				CertOIDCIssuer: issuer,
				IgnoreSCT:      true,
				CertChain:      chainPath,
				SkipTlogVerify: tt.skipTlogVerify,
			}
			blobPath := writeBlobFile(t, td, string(blobBytes), "blob.txt")
			if tt.signature != "" {
				sigPath := writeBlobFile(t, td, tt.signature, "signature.txt")
				cmd.SigRef = sigPath
			}
			if tt.cert != nil {
				certPEM, err := cryptoutils.MarshalCertificateToPEM(tt.cert)
				if err != nil {
					t.Fatal("MarshalCertificateToPEM: %w", err)
				}
				certPath := writeBlobFile(t, td, string(certPEM), "cert.pem")
				cmd.CertRef = certPath
			}
			if tt.key != nil {
				keyPath := writeBlobFile(t, td, string(tt.key), "key.pem")
				cmd.KeyRef = keyPath
			}

			err := cmd.Exec(context.Background(), blobPath)
			if (err != nil) != tt.shouldErr {
				t.Fatalf("verifyBlob()= %s, expected shouldErr=%t ", err, tt.shouldErr)
			}
		})
	}
}

func makeRekorEntry(t *testing.T, rekorSigner signature.ECDSASignerVerifier,
	pyld, sig, svBytes []byte, expiryValid bool) *models.LogEntry {
	ctx := context.Background()
	// Calculate log ID, the digest of the Rekor public key
	logID, err := getLogID(rekorSigner.Public())
	if err != nil {
		t.Fatal(err)
	}

	hashedrekord := &hashedrekord_v001.V001Entry{}
	h := sha256.Sum256(pyld)
	pe, err := hashedrekord.CreateFromArtifactProperties(ctx, types.ArtifactProperties{
		ArtifactHash:   hex.EncodeToString(h[:]),
		SignatureBytes: sig,
		PublicKeyBytes: [][]byte{svBytes},
		PKIFormat:      "x509",
	})
	if err != nil {
		t.Fatal(err)
	}
	entry, err := types.UnmarshalEntry(pe)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := entry.Canonicalize(ctx)
	if err != nil {
		t.Fatal(err)
	}

	integratedTime := time.Now()
	certs, _ := cryptoutils.UnmarshalCertificatesFromPEM(svBytes)
	if len(certs) > 0 {
		if expiryValid {
			integratedTime = certs[0].NotAfter.Add(-time.Second)
		} else {
			integratedTime = certs[0].NotAfter.Add(time.Second)
		}
	}
	e := models.LogEntryAnon{
		Body:           base64.StdEncoding.EncodeToString(leaf),
		IntegratedTime: swag.Int64(integratedTime.Unix()),
		LogIndex:       swag.Int64(0),
		LogID:          swag.String(logID),
	}
	// Marshal payload, sign, and set SET in Bundle
	jsonPayload, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	canonicalized, err := jsoncanonicalizer.Transform(jsonPayload)
	if err != nil {
		t.Fatal(err)
	}
	bundleSig, err := rekorSigner.SignMessage(bytes.NewReader(canonicalized))
	if err != nil {
		t.Fatal(err)
	}
	uuid, _ := cosign.ComputeLeafHash(&e)

	e.Verification = &models.LogEntryAnonVerification{
		SignedEntryTimestamp: bundleSig,
		InclusionProof: &models.InclusionProof{
			LogIndex: swag.Int64(0),
			TreeSize: swag.Int64(1),
			RootHash: swag.String(hex.EncodeToString(uuid)),
			Hashes:   []string{},
		},
	}
	return &models.LogEntry{hex.EncodeToString(uuid): e}
}

func makeLocalBundle(t *testing.T, rekorSigner signature.ECDSASignerVerifier,
	pyld []byte, sig []byte, svBytes []byte, expiryValid bool) string {
	td := t.TempDir()

	// Create bundle.
	entry := makeRekorEntry(t, rekorSigner, pyld, sig, svBytes, expiryValid)
	var e models.LogEntryAnon
	for _, v := range *entry {
		e = v
	}
	b := cosign.LocalSignedPayload{
		Base64Signature: base64.StdEncoding.EncodeToString(sig),
		Cert:            string(svBytes),
		Bundle: &bundle.RekorBundle{
			Payload: bundle.RekorPayload{
				Body:           e.Body,
				IntegratedTime: *e.IntegratedTime,
				LogIndex:       *e.LogIndex,
				LogID:          *e.LogID,
			},
			SignedEntryTimestamp: e.Verification.SignedEntryTimestamp,
		},
	}

	// Write bundle to disk
	jsonBundle, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(td, "bundle.sig")
	if err := os.WriteFile(bundlePath, jsonBundle, 0644); err != nil {
		t.Fatal(err)
	}
	return bundlePath
}

func makeLocalBundleWithoutRekorBundle(t *testing.T, sig []byte, svBytes []byte) string {
	td := t.TempDir()

	b := cosign.LocalSignedPayload{
		Base64Signature: base64.StdEncoding.EncodeToString(sig),
		Cert:            string(svBytes),
	}

	// Write bundle to disk
	jsonBundle, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(td, "bundle.sig")
	if err := os.WriteFile(bundlePath, jsonBundle, 0644); err != nil {
		t.Fatal(err)
	}
	return bundlePath
}

func TestVerifyBlobCmdWithBundle(t *testing.T) {
	keyless := newKeylessStack(t)

	t.Run("Normal verification", func(t *testing.T) {
		identity := "hello@foo.com"
		issuer := "issuer"
		leafCert, _, leafPemCert, signer := keyless.genLeafCert(t, identity, issuer)

		// Create blob
		blob := "someblob"

		// Sign blob with private key
		sig, err := signer.SignMessage(bytes.NewReader([]byte(blob)))
		if err != nil {
			t.Fatal(err)
		}

		// Create bundle
		entry := genRekorEntry(t, hashedrekord.KIND, hashedrekord.New().DefaultVersion(), []byte(blob), leafPemCert, sig)
		b := createBundle(t, sig, leafPemCert, keyless.rekorLogID, leafCert.NotBefore.Unix()+1, entry)
		b.Bundle.SignedEntryTimestamp = keyless.rekorSignPayload(t, b.Bundle.Payload)
		bundlePath := writeBundleFile(t, keyless.td, b, "bundle.json")
		blobPath := writeBlobFile(t, keyless.td, blob, "blob.txt")

		// Verify command
		cmd := VerifyBlobCmd{
			KeyOpts:        options.KeyOpts{BundlePath: bundlePath},
			CertEmail:      identity,
			CertOIDCIssuer: issuer,
			IgnoreSCT:      true,
		}
		if err := cmd.Exec(context.Background(), blobPath); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("Mismatched cert/sig", func(t *testing.T) {
		// This test ensures that the signature and cert at the top level in the LocalSignedPayload must be identical to the ones in the RekorBundle.
		identity := "hello@foo.com"
		issuer := "issuer"
		leafCert, _, leafPemCert, signer := keyless.genLeafCert(t, identity, issuer)
		_, _, leafPemCert2, signer2 := keyless.genLeafCert(t, identity, issuer)

		// Create blob
		blob := "someblob"

		sig, err := signer.SignMessage(bytes.NewReader([]byte(blob)))
		if err != nil {
			t.Fatal(err)
		}

		sig2, err := signer2.SignMessage(bytes.NewReader([]byte(blob)))
		if err != nil {
			t.Fatal(err)
		}

		// Create bundle
		entry := genRekorEntry(t, hashedrekord.KIND, hashedrekord.New().DefaultVersion(), []byte(blob), leafPemCert2, sig2)
		b := createBundle(t, sig, leafPemCert, keyless.rekorLogID, leafCert.NotBefore.Unix()+1, entry)
		b.Bundle.SignedEntryTimestamp = keyless.rekorSignPayload(t, b.Bundle.Payload)
		bundlePath := writeBundleFile(t, keyless.td, b, "bundle.json")
		blobPath := writeBlobFile(t, keyless.td, blob, "blob.txt")

		// Verify command
		cmd := VerifyBlobCmd{
			KeyOpts:   options.KeyOpts{BundlePath: bundlePath},
			IgnoreSCT: true,
		}
		if err := cmd.Exec(context.Background(), blobPath); err == nil {
			t.Fatal("expecting err due to mismatched signatures, got nil")
		}
	})
	t.Run("Expired cert", func(t *testing.T) {
		identity := "hello@foo.com"
		issuer := "issuer"
		leafCert, _, leafPemCert, signer := keyless.genLeafCert(t, identity, issuer)

		// Create blob
		blob := "someblob"

		// Sign blob with private key
		sig, err := signer.SignMessage(bytes.NewReader([]byte(blob)))
		if err != nil {
			t.Fatal(err)
		}

		// Create bundle
		entry := genRekorEntry(t, hashedrekord.KIND, hashedrekord.New().DefaultVersion(), []byte(blob), leafPemCert, sig)
		b := createBundle(t, sig, leafPemCert, keyless.rekorLogID, leafCert.NotBefore.Unix()-1, entry)
		b.Bundle.SignedEntryTimestamp = keyless.rekorSignPayload(t, b.Bundle.Payload)
		bundlePath := writeBundleFile(t, keyless.td, b, "bundle.json")
		blobPath := writeBlobFile(t, keyless.td, blob, "blob.txt")

		// Verify command
		cmd := VerifyBlobCmd{
			KeyOpts:   options.KeyOpts{BundlePath: bundlePath},
			IgnoreSCT: true,
		}

		if err := cmd.Exec(context.Background(), blobPath); err == nil {
			t.Fatal("expected error due to expired cert, received nil")
		}
	})
	t.Run("Attestation", func(t *testing.T) {
		identity := "hello@foo.com"
		issuer := "issuer"
		leafCert, _, leafPemCert, signer := keyless.genLeafCert(t, identity, issuer)

		stmt := `{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"customFoo","subject":[{"name":"subject","digest":{"sha256":"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}}],"predicate":{}}`
		wrapped := dsse.WrapSigner(signer, ctypes.IntotoPayloadType)
		signedPayload, err := wrapped.SignMessage(bytes.NewReader([]byte(stmt)), signatureoptions.WithContext(context.Background()))
		if err != nil {
			t.Fatal(err)
		}
		// intoto sig = json-serialized dsse envelope
		sig := signedPayload

		// Create bundle
		entry := genRekorEntry(t, intoto.KIND, "0.0.1", signedPayload, leafPemCert, sig)
		b := createBundle(t, sig, leafPemCert, keyless.rekorLogID, leafCert.NotBefore.Unix()+1, entry)
		b.Bundle.SignedEntryTimestamp = keyless.rekorSignPayload(t, b.Bundle.Payload)
		bundlePath := writeBundleFile(t, keyless.td, b, "bundle.json")
		blobPath := writeBlobFile(t, keyless.td, string(signedPayload), "attestation.txt")

		// Verify command
		cmd := VerifyBlobCmd{
			CertRef:   "", // Cert is fetched from bundle
			CertChain: "", // Chain is fetched from TUF/SIGSTORE_ROOT_FILE
			SigRef:    "", // Sig is fetched from bundle
			KeyOpts:   options.KeyOpts{BundlePath: bundlePath},
			IgnoreSCT: true,
		}
		if err := cmd.Exec(context.Background(), blobPath); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("Invalid blob signature", func(t *testing.T) {
		identity := "hello@foo.com"
		issuer := "issuer"
		leafCert, _, leafPemCert, signer := keyless.genLeafCert(t, identity, issuer)

		// Create blob
		blob := "someblob"

		// Sign blob with private key
		sig, err := signer.SignMessage(bytes.NewReader([]byte(blob)))
		if err != nil {
			t.Fatal(err)
		}

		// Create bundle
		entry := genRekorEntry(t, hashedrekord.KIND, hashedrekord.New().DefaultVersion(), []byte(blob), leafPemCert, sig)
		b := createBundle(t, sig, leafPemCert, keyless.rekorLogID, leafCert.NotBefore.Unix()+1, entry)
		b.Bundle.SignedEntryTimestamp = []byte{'i', 'n', 'v', 'a', 'l', 'i', 'd'}
		bundlePath := writeBundleFile(t, keyless.td, b, "bundle.json")
		blobPath := writeBlobFile(t, keyless.td, blob, "blob.txt")

		// Verify command
		cmd := VerifyBlobCmd{
			CertRef:   "", // Cert is fetched from bundle
			CertChain: "", // Chain is fetched from TUF/SIGSTORE_ROOT_FILE
			SigRef:    "", // Sig is fetched from bundle
			KeyOpts:   options.KeyOpts{BundlePath: bundlePath},
			IgnoreSCT: true,
		}
		err = cmd.Exec(context.Background(), blobPath)
		if err == nil || !strings.Contains(err.Error(), "unable to verify SET") {
			t.Fatalf("expected error verifying SET, got %v", err)
		}
	})
	t.Run("Mismatched certificate email", func(t *testing.T) {
		identity := "hello@foo.com"
		issuer := "issuer"
		leafCert, _, leafPemCert, signer := keyless.genLeafCert(t, identity, issuer)

		// Create blob
		blob := "someblob"

		// Sign blob with private key
		sig, err := signer.SignMessage(bytes.NewReader([]byte(blob)))
		if err != nil {
			t.Fatal(err)
		}

		// Create bundle
		entry := genRekorEntry(t, hashedrekord.KIND, hashedrekord.New().DefaultVersion(), []byte(blob), leafPemCert, sig)
		b := createBundle(t, sig, leafPemCert, keyless.rekorLogID, leafCert.NotBefore.Unix()+1, entry)
		b.Bundle.SignedEntryTimestamp = keyless.rekorSignPayload(t, b.Bundle.Payload)
		bundlePath := writeBundleFile(t, keyless.td, b, "bundle.json")
		blobPath := writeBlobFile(t, keyless.td, blob, "blob.txt")

		// Verify command
		cmd := VerifyBlobCmd{
			KeyOpts:        options.KeyOpts{BundlePath: bundlePath},
			CertRef:        "", // Cert is fetched from bundle
			CertOIDCIssuer: issuer,
			CertEmail:      "invalid@example.com",
			CertChain:      "", // Chain is fetched from TUF/SIGSTORE_ROOT_FILE
			SigRef:         "", // Sig is fetched from bundle
			IgnoreSCT:      true,
		}
		err = cmd.Exec(context.Background(), blobPath)
		if err == nil || !strings.Contains(err.Error(), "expected identity not found in certificate") {
			t.Fatalf("expected error with mismatched identity, got %v", err)
		}
	})
	t.Run("Mismatched certificate issuer", func(t *testing.T) {
		identity := "hello@foo.com"
		issuer := "issuer"
		leafCert, _, leafPemCert, signer := keyless.genLeafCert(t, identity, issuer)

		// Create blob
		blob := "someblob"

		// Sign blob with private key
		sig, err := signer.SignMessage(bytes.NewReader([]byte(blob)))
		if err != nil {
			t.Fatal(err)
		}

		// Create bundle
		entry := genRekorEntry(t, hashedrekord.KIND, hashedrekord.New().DefaultVersion(), []byte(blob), leafPemCert, sig)
		b := createBundle(t, sig, leafPemCert, keyless.rekorLogID, leafCert.NotBefore.Unix()+1, entry)
		b.Bundle.SignedEntryTimestamp = keyless.rekorSignPayload(t, b.Bundle.Payload)
		bundlePath := writeBundleFile(t, keyless.td, b, "bundle.json")
		blobPath := writeBlobFile(t, keyless.td, blob, "blob.txt")

		// Verify command
		cmd := VerifyBlobCmd{
			CertRef:        "", // Cert is fetched from bundle
			CertOIDCIssuer: "invalid",
			CertEmail:      identity,
			CertChain:      "", // Chain is fetched from TUF/SIGSTORE_ROOT_FILE
			SigRef:         "", // Sig is fetched from bundle
			KeyOpts:        options.KeyOpts{BundlePath: bundlePath},
			IgnoreSCT:      true,
		}
		err = cmd.Exec(context.Background(), blobPath)
		if err == nil || !strings.Contains(err.Error(), "expected oidc issuer not found in certificate") {
			t.Fatalf("expected error with mismatched issuer, got %v", err)
		}
	})
	t.Run("Implicit Fulcio chain with bundle in non-experimental mode", func(t *testing.T) {
		identity := "hello@foo.com"
		issuer := "issuer"
		leafCert, _, leafPemCert, signer := keyless.genLeafCert(t, identity, issuer)

		// Create blob
		blob := "someblob"

		// Sign blob with private key
		sig, err := signer.SignMessage(bytes.NewReader([]byte(blob)))
		if err != nil {
			t.Fatal(err)
		}

		// Create bundle
		entry := genRekorEntry(t, hashedrekord.KIND, hashedrekord.New().DefaultVersion(), []byte(blob), leafPemCert, sig)
		b := createBundle(t, sig, leafPemCert, keyless.rekorLogID, leafCert.NotBefore.Unix()+1, entry)
		b.Bundle.SignedEntryTimestamp = keyless.rekorSignPayload(t, b.Bundle.Payload)
		bundlePath := writeBundleFile(t, keyless.td, b, "bundle.json")
		blobPath := writeBlobFile(t, keyless.td, blob, "blob.txt")
		certPath := writeBlobFile(t, keyless.td, string(leafPemCert), "cert.pem")

		// Verify command
		cmd := VerifyBlobCmd{
			CertRef:        certPath,
			CertOIDCIssuer: issuer,
			CertEmail:      identity,
			CertChain:      "", // Chain is fetched from TUF/SIGSTORE_ROOT_FILE
			SigRef:         "", // Sig is fetched from bundle
			KeyOpts:        options.KeyOpts{BundlePath: bundlePath},
			IgnoreSCT:      true,
		}
		err = cmd.Exec(context.Background(), blobPath)
		if err != nil {
			t.Fatalf("expected success without specifying the intermediates, got %v", err)
		}
	})
	t.Run("Explicit Fulcio chain with rekor and timestamp bundles in non-experimental mode", func(t *testing.T) {
		identity := "hello@foo.com"
		issuer := "issuer"
		leafCert, _, leafPemCert, signer := keyless.genLeafCert(t, identity, issuer)

		// Create blob
		blob := "someblob"

		// Sign blob with private key
		sig, err := signer.SignMessage(bytes.NewReader([]byte(blob)))
		if err != nil {
			t.Fatal(err)
		}

		// TODO: Replace with a full TSA mock client, related to https://github.com/sigstore/timestamp-authority/issues/146
		viper.Set("timestamp-signer", "memory")
		apiServer := server.NewRestAPIServer("localhost", 0, []string{"http"}, 10*time.Second, 10*time.Second)
		server := httptest.NewServer(apiServer.GetHandler())
		t.Cleanup(server.Close)

		client, err := tsaclient.GetTimestampClient(server.URL)
		if err != nil {
			t.Error(err)
		}

		payloadSigner := payload.NewSigner(keyless.rekorSigner)

		tsaSigner := tsa.NewSigner(payloadSigner, client)
		var sigTSA oci.Signature
		sigTSA, _, err = tsaSigner.Sign(context.Background(), bytes.NewReader([]byte(blob)))
		if err != nil {
			t.Fatalf("error signing the payload with the rekor and tsa clients: %v", err)
		}

		rfc3161Timestamp, err := sigTSA.RFC3161Timestamp()
		if err != nil {
			t.Fatalf("unexpected error getting rfc3161 timestamp bundle: %v", err)
		}

		chain, err := client.Timestamp.GetTimestampCertChain(nil)
		if err != nil {
			t.Fatalf("unexpected error getting timestamp chain: %v", err)
		}

		tsaCertChainPath := filepath.Join(keyless.td, "tsacertchain.pem")
		if err := os.WriteFile(tsaCertChainPath, []byte(chain.Payload), 0644); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tsaCertChainPath)

		// Create bundle
		entry := genRekorEntry(t, hashedrekord.KIND, hashedrekord.New().DefaultVersion(), []byte(blob), leafPemCert, sig)
		b := createRFC3161TimestampAndOrRekorBundle(t, sig, leafPemCert, keyless.rekorLogID, leafCert.NotBefore.Unix()+1, entry, rfc3161Timestamp.SignedRFC3161Timestamp)
		b.Bundle.SignedEntryTimestamp = keyless.rekorSignPayload(t, b.Bundle.Payload)
		bundlePath := writeBundleFile(t, keyless.td, b, "bundle.json")
		blobPath := writeBlobFile(t, keyless.td, blob, "blob.txt")

		// Verify command
		cmd := VerifyBlobCmd{
			CertOIDCIssuer: issuer,
			CertEmail:      identity,
			CertChain:      os.Getenv("SIGSTORE_ROOT_FILE"),
			SigRef:         "", // Sig is fetched from bundle
			KeyOpts:        options.KeyOpts{BundlePath: bundlePath, TSACertChainPath: tsaCertChainPath},
			IgnoreSCT:      true,
		}
		err = cmd.Exec(context.Background(), blobPath)
		if err != nil {
			t.Fatalf("expected success specifying the intermediates, got %v", err)
		}
	})
	t.Run("Explicit Fulcio chain with bundle in non-experimental mode", func(t *testing.T) {
		identity := "hello@foo.com"
		issuer := "issuer"
		leafCert, _, leafPemCert, signer := keyless.genLeafCert(t, identity, issuer)

		// Create blob
		blob := "someblob"

		// Sign blob with private key
		sig, err := signer.SignMessage(bytes.NewReader([]byte(blob)))
		if err != nil {
			t.Fatal(err)
		}

		// Create bundle
		entry := genRekorEntry(t, hashedrekord.KIND, hashedrekord.New().DefaultVersion(), []byte(blob), leafPemCert, sig)
		b := createBundle(t, sig, leafPemCert, keyless.rekorLogID, leafCert.NotBefore.Unix()+1, entry)
		b.Bundle.SignedEntryTimestamp = keyless.rekorSignPayload(t, b.Bundle.Payload)
		bundlePath := writeBundleFile(t, keyless.td, b, "bundle.json")
		blobPath := writeBlobFile(t, keyless.td, blob, "blob.txt")

		// Verify command
		cmd := VerifyBlobCmd{
			CertOIDCIssuer: issuer,
			CertEmail:      identity,
			CertChain:      os.Getenv("SIGSTORE_ROOT_FILE"),
			SigRef:         "", // Sig is fetched from bundle
			KeyOpts:        options.KeyOpts{BundlePath: bundlePath},
			IgnoreSCT:      true,
		}
		err = cmd.Exec(context.Background(), blobPath)
		if err != nil {
			t.Fatalf("expected success specifying the intermediates, got %v", err)
		}
	})
	t.Run("Explicit Fulcio mismatched chain failure", func(t *testing.T) {
		identity := "hello@foo.com"
		issuer := "issuer"
		leafCert, _, leafPemCert, signer := keyless.genLeafCert(t, identity, issuer)

		// Create blob
		blob := "someblob"

		// Sign blob with private key
		sig, err := signer.SignMessage(bytes.NewReader([]byte(blob)))
		if err != nil {
			t.Fatal(err)
		}

		// Create bundle
		entry := genRekorEntry(t, hashedrekord.KIND, hashedrekord.New().DefaultVersion(), []byte(blob), leafPemCert, sig)
		b := createBundle(t, sig, leafPemCert, keyless.rekorLogID, leafCert.NotBefore.Unix()+1, entry)
		b.Bundle.SignedEntryTimestamp = keyless.rekorSignPayload(t, b.Bundle.Payload)
		bundlePath := writeBundleFile(t, keyless.td, b, "bundle.json")
		blobPath := writeBlobFile(t, keyless.td, blob, "blob.txt")

		rootCert, _, _ := test.GenerateRootCa()
		rootPemCert, _ := cryptoutils.MarshalCertificateToPEM(rootCert)
		tmpChainFile, err := os.CreateTemp(t.TempDir(), "cosign_fulcio_root_*.cert")
		if err != nil {
			t.Fatalf("failed to create temp chain file: %v", err)
		}
		defer tmpChainFile.Close()
		if _, err := tmpChainFile.Write(rootPemCert); err != nil {
			t.Fatalf("failed to write chain file: %v", err)
		}

		// Verify command
		cmd := VerifyBlobCmd{
			CertOIDCIssuer: issuer,
			CertEmail:      identity,
			CertChain:      tmpChainFile.Name(),
			SigRef:         "", // Sig is fetched from bundle
			KeyOpts:        options.KeyOpts{BundlePath: bundlePath},
			IgnoreSCT:      true,
		}
		err = cmd.Exec(context.Background(), blobPath)
		if err == nil || !strings.Contains(err.Error(), "x509: certificate signed by unknown authority") {
			t.Fatalf("expected error with mismatched root, got %v", err)
		}
	})
}

func TestVerifyBlobCmdInvalidRootCA(t *testing.T) {
	keyless := newKeylessStack(t)
	// Change the keyless stack.
	_ = newKeylessStack(t)
	t.Run("Invalid certificate root when specifying cert via certRef", func(t *testing.T) {
		identity := "hello@foo.com"
		issuer := "issuer"
		leafCert, _, leafPemCert, signer := keyless.genLeafCert(t, identity, issuer)

		// Create blob
		blob := "someblob"

		// Sign blob with private key
		sig, err := signer.SignMessage(bytes.NewReader([]byte(blob)))
		if err != nil {
			t.Fatal(err)
		}

		// Create bundle
		entry := genRekorEntry(t, hashedrekord.KIND, hashedrekord.New().DefaultVersion(), []byte(blob), leafPemCert, sig)
		b := createBundle(t, sig, leafPemCert, keyless.rekorLogID, leafCert.NotBefore.Unix()+1, entry)
		b.Bundle.SignedEntryTimestamp = keyless.rekorSignPayload(t, b.Bundle.Payload)
		bundlePath := writeBundleFile(t, keyless.td, b, "bundle.json")
		blobPath := writeBlobFile(t, keyless.td, blob, "blob.txt")
		certPath := writeBlobFile(t, keyless.td, string(leafPemCert), "cert.pem")

		// Verify command
		cmd := VerifyBlobCmd{
			CertRef:        certPath,
			CertOIDCIssuer: issuer,
			CertEmail:      identity,
			CertChain:      "", // Chain is fetched from TUF/SIGSTORE_ROOT_FILE
			SigRef:         "", // Sig is fetched from bundle
			KeyOpts:        options.KeyOpts{BundlePath: bundlePath},
			IgnoreSCT:      true,
		}
		err = cmd.Exec(context.Background(), blobPath)
		if err == nil || !strings.Contains(err.Error(), "certificate signed by unknown authority") {
			t.Fatalf("expected error with invalid root CA, got %v", err)
		}
	})
	t.Run("Invalid certificate root when specifying cert in bundle", func(t *testing.T) {
		identity := "hello@foo.com"
		issuer := "issuer"
		leafCert, _, leafPemCert, signer := keyless.genLeafCert(t, identity, issuer)

		// Create blob
		blob := "someblob"

		// Sign blob with private key
		sig, err := signer.SignMessage(bytes.NewReader([]byte(blob)))
		if err != nil {
			t.Fatal(err)
		}

		// Create bundle
		entry := genRekorEntry(t, hashedrekord.KIND, hashedrekord.New().DefaultVersion(), []byte(blob), leafPemCert, sig)
		b := createBundle(t, sig, leafPemCert, keyless.rekorLogID, leafCert.NotBefore.Unix()+1, entry)
		b.Bundle.SignedEntryTimestamp = keyless.rekorSignPayload(t, b.Bundle.Payload)
		bundlePath := writeBundleFile(t, keyless.td, b, "bundle.json")
		blobPath := writeBlobFile(t, keyless.td, blob, "blob.txt")

		// Verify command
		cmd := VerifyBlobCmd{
			CertRef:        "",
			CertOIDCIssuer: issuer, // Fetched from bundle
			CertEmail:      identity,
			CertChain:      "", // Chain is fetched from TUF/SIGSTORE_ROOT_FILE
			SigRef:         "", // Sig is fetched from bundle
			KeyOpts:        options.KeyOpts{BundlePath: bundlePath},
			IgnoreSCT:      true,
		}
		err = cmd.Exec(context.Background(), blobPath)
		if err == nil || !strings.Contains(err.Error(), "certificate signed by unknown authority") {
			t.Fatalf("expected error with invalid root CA, got %v", err)
		}
	})
}

type keylessStack struct {
	rootCert    *x509.Certificate
	rootPriv    *ecdsa.PrivateKey
	rootPemCert []byte
	subCert     *x509.Certificate
	subPriv     *ecdsa.PrivateKey
	subPemCert  []byte
	rekorSigner *signature.ECDSASignerVerifier
	rekorLogID  string
	td          string // temporary directory
}

func newKeylessStack(t *testing.T) *keylessStack {
	stack := &keylessStack{td: t.TempDir()}
	stack.rootCert, stack.rootPriv, _ = test.GenerateRootCa()
	stack.rootPemCert, _ = cryptoutils.MarshalCertificateToPEM(stack.rootCert)
	stack.subCert, stack.subPriv, _ = test.GenerateSubordinateCa(stack.rootCert, stack.rootPriv)
	stack.subPemCert, _ = cryptoutils.MarshalCertificateToPEM(stack.subCert)

	stack.genChainFile(t)
	stack.genRekor(t)
	return stack
}

func (s *keylessStack) genLeafCert(t *testing.T, subject string, issuer string) (*x509.Certificate, *ecdsa.PrivateKey, []byte, *signature.ECDSASignerVerifier) { //nolint: unparam
	cert, priv, _ := test.GenerateLeafCert(subject, issuer, s.subCert, s.subPriv)
	pemCert, _ := cryptoutils.MarshalCertificateToPEM(cert)
	signer, err := signature.LoadECDSASignerVerifier(priv, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return cert, priv, pemCert, signer
}

func (s *keylessStack) genChainFile(t *testing.T) {
	var chain []byte
	chain = append(chain, s.subPemCert...)
	chain = append(chain, s.rootPemCert...)
	tmpChainFile, err := os.CreateTemp(s.td, "cosign_fulcio_chain_*.cert")
	if err != nil {
		t.Fatalf("failed to create temp chain file: %v", err)
	}
	defer tmpChainFile.Close()
	if _, err := tmpChainFile.Write(chain); err != nil {
		t.Fatalf("failed to write chain file: %v", err)
	}
	// Override for Fulcio root so it doesn't use TUF
	t.Setenv("SIGSTORE_ROOT_FILE", tmpChainFile.Name())
}

func (s *keylessStack) genRekor(t *testing.T) {
	// Create Rekor private key and write to disk
	rekorPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s.rekorSigner, err = signature.LoadECDSASignerVerifier(rekorPriv, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	rekorPub := s.rekorSigner.Public()
	pemRekor, err := cryptoutils.MarshalPublicKeyToPEM(rekorPub)
	if err != nil {
		t.Fatal(err)
	}
	tmpRekorPubFile, err := os.CreateTemp(s.td, "cosign_rekor_pub_*.key")
	if err != nil {
		t.Fatalf("failed to create temp rekor pub file: %v", err)
	}
	defer tmpRekorPubFile.Close()
	if _, err := tmpRekorPubFile.Write(pemRekor); err != nil {
		t.Fatalf("failed to write rekor pub file: %v", err)
	}

	// Calculate log ID, the digest of the Rekor public key
	s.rekorLogID, err = getLogID(rekorPub)
	if err != nil {
		t.Fatal(err)
	}
	// Override for Rekor public key so it doesn't use TUF
	t.Setenv("SIGSTORE_REKOR_PUBLIC_KEY", tmpRekorPubFile.Name())
}
func (s *keylessStack) rekorSignPayload(t *testing.T, payload bundle.RekorPayload) []byte {
	// Marshal payload, sign, and return SET
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	canonicalized, err := jsoncanonicalizer.Transform(jsonPayload)
	if err != nil {
		t.Fatal(err)
	}
	bundleSig, err := s.rekorSigner.SignMessage(bytes.NewReader(canonicalized))
	if err != nil {
		t.Fatal(err)
	}
	return bundleSig
}

// getLogID calculates the digest of a PKIX-encoded public key
func getLogID(pub crypto.PublicKey) (string, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(pubBytes)
	return hex.EncodeToString(digest[:]), nil
}

func genRekorEntry(t *testing.T, kind, version string, artifact []byte, cert []byte, sig []byte) string {
	// Generate the Rekor Entry
	entryImpl, err := createEntry(context.Background(), kind, version, artifact, cert, sig)
	if err != nil {
		t.Fatal(err)
	}
	entryBytes, err := entryImpl.Canonicalize(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(entryBytes)
}

func createBundle(_ *testing.T, sig []byte, certPem []byte, logID string, integratedTime int64, rekorEntry string) *cosign.LocalSignedPayload {
	// Create bundle with:
	// * Blob signature
	// * Signing certificate
	// * Bundle with a payload and signature over the payload
	b := &cosign.LocalSignedPayload{
		Base64Signature: base64.StdEncoding.EncodeToString(sig),
		Cert:            string(certPem),
		Bundle: &bundle.RekorBundle{
			SignedEntryTimestamp: []byte{},
			Payload: bundle.RekorPayload{
				LogID:          logID,
				IntegratedTime: integratedTime,
				LogIndex:       1,
				Body:           rekorEntry,
			},
		},
	}

	return b
}

func createRFC3161TimestampAndOrRekorBundle(_ *testing.T, sig []byte, certPem []byte, logID string, integratedTime int64, rekorEntry string, rfc3161timestamp []byte) *cosign.LocalSignedPayload {
	// Create bundle with:
	// * Blob signature
	// * Signing certificate
	b := &cosign.LocalSignedPayload{
		Base64Signature: base64.StdEncoding.EncodeToString(sig),
		Cert:            string(certPem),
	}

	if rekorEntry != "" {
		// * Bundle with a payload and signature over the payload
		b.Bundle = &bundle.RekorBundle{
			SignedEntryTimestamp: []byte{},
			Payload: bundle.RekorPayload{
				LogID:          logID,
				IntegratedTime: integratedTime,
				LogIndex:       1,
				Body:           rekorEntry,
			},
		}
	}

	if rfc3161timestamp != nil {
		b.RFC3161Timestamp = &bundle.RFC3161Timestamp{
			SignedRFC3161Timestamp: rfc3161timestamp,
		}
	}

	return b
}

func createEntry(ctx context.Context, kind, apiVersion string, blobBytes, certBytes, sigBytes []byte) (types.EntryImpl, error) {
	props := types.ArtifactProperties{
		PublicKeyBytes: [][]byte{certBytes},
		PKIFormat:      string(pki.X509),
	}
	switch kind {
	case rekord.KIND:
		props.ArtifactBytes = blobBytes
		props.SignatureBytes = sigBytes
	case hashedrekord.KIND:
		blobHash := sha256.Sum256(blobBytes)
		props.ArtifactHash = strings.ToLower(hex.EncodeToString(blobHash[:]))
		props.SignatureBytes = sigBytes
	case intoto.KIND:
		props.ArtifactBytes = blobBytes
	default:
		return nil, fmt.Errorf("unexpected entry kind: %s", kind)
	}
	proposedEntry, err := types.NewProposedEntry(ctx, kind, apiVersion, props)
	if err != nil {
		return nil, err
	}
	eimpl, err := types.CreateVersionedEntry(proposedEntry)
	if err != nil {
		return nil, err
	}

	can, err := types.CanonicalizeEntry(ctx, eimpl)
	if err != nil {
		return nil, err
	}
	proposedEntryCan, err := models.UnmarshalProposedEntry(bytes.NewReader(can), runtime.JSONConsumer())
	if err != nil {
		return nil, err
	}

	return types.UnmarshalEntry(proposedEntryCan)
}

func writeBundleFile(t *testing.T, td string, b *cosign.LocalSignedPayload, name string) string { //nolint: unparam
	// Write bundle to disk
	jsonBundle, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(td, name)
	if err := os.WriteFile(bundlePath, jsonBundle, 0644); err != nil {
		t.Fatal(err)
	}
	return bundlePath
}

func writeBlobFile(t *testing.T, td string, blob string, name string) string {
	// Write blob to disk
	blobPath := filepath.Join(td, name)
	if err := os.WriteFile(blobPath, []byte(blob), 0644); err != nil {
		t.Fatal(err)
	}
	return blobPath
}
