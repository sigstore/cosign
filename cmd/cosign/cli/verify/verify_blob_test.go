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
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	sigs "github.com/sigstore/cosign/v3/pkg/signature"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
	"google.golang.org/protobuf/encoding/protojson"
)

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

	var makeSignature = func(blob []byte, signer signature.SignerVerifier) string {
		sig, err := signer.SignMessage(bytes.NewReader(blob))
		if err != nil {
			t.Fatal(err)
		}
		return string(sig)
	}
	blobBytes := []byte("foo")
	blobSignature := makeSignature(blobBytes, signer)

	otherBytes := []byte("bar")
	otherSignature := makeSignature(otherBytes, signer)

	tts := []struct {
		name       string
		blob       []byte
		key        []byte
		bundlePath string
		newBundle  bool
		// The rekor entry response when Rekor is enabled
		rekorEntry     []*models.LogEntry
		skipTlogVerify bool
		shouldErr      bool
		tsPath         string
		tsChainPath    string
	}{{
		name:           "valid signature with public key - new bundle",
		blob:           blobBytes,
		key:            pubKeyBytes,
		bundlePath:     makeLocalNewBundle(t, []byte(blobSignature), sha256.Sum256(blobBytes)),
		newBundle:      true,
		skipTlogVerify: true,
		shouldErr:      false,
	},
		{
			name:           "invalid signature with public key - new bundle",
			blob:           blobBytes,
			key:            pubKeyBytes,
			bundlePath:     makeLocalNewBundle(t, []byte(otherSignature), sha256.Sum256(blobBytes)),
			newBundle:      true,
			skipTlogVerify: true,
			shouldErr:      true,
		},
	}
	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt
			entries := make([]models.LogEntry, 0, len(tt.rekorEntry))
			for _, entry := range tt.rekorEntry {
				entries = append(entries, *entry)
			}
			testServer := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(entries)
				}))
			defer testServer.Close()

			// Verify command
			cmd := VerifyBlobCmd{
				KeyOpts: options.KeyOpts{
					BundlePath:           tt.bundlePath,
					RFC3161TimestampPath: tt.tsPath,
					TSACertChainPath:     tt.tsChainPath,
				},
				CertVerifyOptions: options.CertVerifyOptions{
					CertIdentity:   identity,
					CertOidcIssuer: issuer,
				},
				IgnoreSCT:  true,
				IgnoreTlog: tt.skipTlogVerify,
			}
			blobPath := writeBlobFile(t, td, string(blobBytes), "blob.txt")
			if tt.key != nil {
				keyPath := writeBlobFile(t, td, string(tt.key), "key.pem")
				cmd.KeyRef = keyPath
				cmd.CertVerifyOptions = options.CertVerifyOptions{}
			}
			if tt.newBundle {
				cmd.TrustedRootPath = writeTrustedRootFile(t, td, "{\"mediaType\":\"application/vnd.dev.sigstore.trustedroot+json;version=0.1\"}")
				cmd.RFC3161TimestampPath = ""
				cmd.TSACertChainPath = ""
			}
			err := cmd.Exec(context.Background(), blobPath)
			if (err != nil) != tt.shouldErr {
				t.Fatalf("verifyBlob()= %s, expected shouldErr=%t ", err, tt.shouldErr)
			}
		})
	}
}

func TestVerifyBlobCertMissingSubject(t *testing.T) {
	ctx := context.Background()

	verifyBlob := VerifyBlobCmd{
		CertVerifyOptions: options.CertVerifyOptions{
			CertOidcIssuer: "issuer",
		},
	}
	err := verifyBlob.Exec(ctx, "blob")
	if err == nil {
		t.Fatalf("verifyBlob() expected '--certificate-identity required'")
	}
}

func TestVerifyBlobMutuallyExclusiveFlags(t *testing.T) {
	ctx := context.Background()
	tts := []struct {
		name          string
		cmd           VerifyBlobCmd
		expectedError error
	}{
		{
			name: "both key and cert identity",
			cmd: VerifyBlobCmd{
				KeyOpts: options.KeyOpts{
					KeyRef:     "key.pub",
					BundlePath: "bundle.sigstore.json",
				},
				CertVerifyOptions: options.CertVerifyOptions{
					CertIdentity: "hello@foo.com",
				},
			},
			expectedError: &options.KeyAndIdentityParseError{},
		},
		{
			name: "both key and cert identity regex",
			cmd: VerifyBlobCmd{
				KeyOpts: options.KeyOpts{
					KeyRef:     "key.pub",
					BundlePath: "bundle.sigstore.json",
				},
				CertVerifyOptions: options.CertVerifyOptions{
					CertIdentityRegexp: "^.*@foo.com$",
				},
			},
			expectedError: &options.KeyAndIdentityParseError{},
		},
		{
			name: "both cert identity and cert identity regex",
			cmd: VerifyBlobCmd{
				KeyOpts: options.KeyOpts{
					BundlePath: "bundle.sigstore.json",
				},
				CertVerifyOptions: options.CertVerifyOptions{
					CertIdentity:       "hello@foo.com",
					CertIdentityRegexp: "^.*@foo.com$",
				},
			},
			expectedError: &options.KeyAndIdentityParseError{},
		},
		{
			name: "both key and secret key",
			cmd: VerifyBlobCmd{
				KeyOpts: options.KeyOpts{
					KeyRef: "key.pub",
					Sk:     true,
				},
			},
			expectedError: &options.PubKeyParseError{},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Exec(ctx, "foo")
			if !errors.Is(err, tt.expectedError) {
				t.Fatalf("expected %T, got: %T, %v", tt.expectedError, err, err)
			}
		})
	}
}

func TestVerifyBlobKeyAndCertIdentity(t *testing.T) {
	ctx := context.Background()
	verifyBlob := VerifyBlobCmd{
		KeyOpts: options.KeyOpts{
			KeyRef: "key.pub",
		},
		CertVerifyOptions: options.CertVerifyOptions{
			CertIdentity: "hello@foo.com",
		},
	}
	var expectedErr *options.KeyAndIdentityParseError
	err := verifyBlob.Exec(ctx, "blob")
	if !errors.As(err, &expectedErr) {
		t.Fatalf("expected KeyAndIdentityParseError, got: %T, %v", err, err)
	}
}

func makeLocalNewBundle(t *testing.T, sig []byte, digest [32]byte) string {
	b := &protobundle.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_PublicKey{
				PublicKey: &protocommon.PublicKeyIdentifier{
					Hint: "hint",
				},
			},
		},
	}

	b.Content = &protobundle.Bundle_MessageSignature{
		MessageSignature: &protocommon.MessageSignature{
			MessageDigest: &protocommon.HashOutput{
				Algorithm: protocommon.HashAlgorithm_SHA2_256,
				Digest:    digest[:],
			},
			Signature: sig,
		},
	}

	contents, err := protojson.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}

	// write bundle to disk
	td := t.TempDir()
	bundlePath := filepath.Join(td, "bundle.sigstore.json")
	if err := os.WriteFile(bundlePath, contents, 0644); err != nil {
		t.Fatal(err)
	}
	return bundlePath
}

// getLogID calculates the digest of a PKIX-encoded public key

func writeBlobFile(t *testing.T, td string, blob string, name string) string {
	// Write blob to disk
	blobPath := filepath.Join(td, name)
	if err := os.WriteFile(blobPath, []byte(blob), 0644); err != nil {
		t.Fatal(err)
	}
	return blobPath
}

func writeTrustedRootFile(t *testing.T, td, contents string) string { //nolint: unparam
	path := filepath.Join(td, "trusted_root.json")
	if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}
