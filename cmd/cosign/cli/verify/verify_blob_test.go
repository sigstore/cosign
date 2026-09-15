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
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	sigs "github.com/sigstore/cosign/v3/pkg/signature"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
	"google.golang.org/protobuf/encoding/protojson"
)

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

	var makeSignature = func(blob []byte, s signature.SignerVerifier) string {
		sig, err := s.SignMessage(bytes.NewReader(blob))
		if err != nil {
			t.Fatal(err)
		}
		return string(sig)
	}
	blobBytes := []byte("foo")
	blobSignature := makeSignature(blobBytes, signer)

	otherBytes := []byte("bar")
	otherSignature := makeSignature(otherBytes, signer)

	blobDigest := sha256.Sum256(blobBytes)
	blobDigestRef := "sha256:" + hex.EncodeToString(blobDigest[:])

	tts := []struct {
		name        string
		blobRef     string
		key         []byte
		bundlePath  string
		shouldErr   bool
		expectedErr string
	}{
		{
			name:       "valid signature with public key - new bundle",
			blobRef:    writeBlobFile(t, td, string(blobBytes), "blob.txt"),
			key:        pubKeyBytes,
			bundlePath: makeLocalNewBundle(t, []byte(blobSignature), blobDigest),
			shouldErr:  false,
		},
		{
			name:        "invalid signature with public key - new bundle",
			blobRef:     writeBlobFile(t, td, string(blobBytes), "blob.txt"),
			key:         pubKeyBytes,
			bundlePath:  makeLocalNewBundle(t, []byte(otherSignature), blobDigest),
			shouldErr:   true,
			expectedErr: "invalid signature",
		},
		{
			name:       "mismatched blob content - new bundle",
			blobRef:    writeBlobFile(t, td, string(otherBytes), "other_blob.txt"),
			key:        pubKeyBytes,
			bundlePath: makeLocalNewBundle(t, []byte(blobSignature), blobDigest),
			shouldErr:  true,
		},
		{
			name:       "valid signature with artifact digest blobRef",
			blobRef:    blobDigestRef,
			key:        pubKeyBytes,
			bundlePath: makeLocalNewBundle(t, []byte(blobSignature), blobDigest),
			shouldErr:  false,
		},
		{
			name:        "invalid signature with artifact digest blobRef",
			blobRef:     blobDigestRef,
			key:         pubKeyBytes,
			bundlePath:  makeLocalNewBundle(t, []byte(otherSignature), blobDigest),
			shouldErr:   true,
			expectedErr: "invalid signature",
		},
		{
			name:        "missing bundle path",
			blobRef:     writeBlobFile(t, td, string(blobBytes), "blob.txt"),
			key:         pubKeyBytes,
			bundlePath:  "",
			shouldErr:   true,
			expectedErr: "please specify --bundle",
		},
		{
			name:       "non-existent bundle path",
			blobRef:    writeBlobFile(t, td, string(blobBytes), "blob.txt"),
			key:        pubKeyBytes,
			bundlePath: filepath.Join(td, "nonexistent.bundle.json"),
			shouldErr:  true,
		},
	}
	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			cmd := VerifyBlobCmd{
				KeyOpts: options.KeyOpts{
					BundlePath: tt.bundlePath,
				},
				IgnoreSCT:  true,
				IgnoreTlog: true,
			}
			if tt.key != nil {
				keyPath := writeBlobFile(t, td, string(tt.key), "key.pem")
				cmd.KeyRef = keyPath
			}
			cmd.TrustedRootPath = writeTrustedRootFile(t, td, "{\"mediaType\":\"application/vnd.dev.sigstore.trustedroot+json;version=0.1\"}")
			err := cmd.Exec(context.Background(), tt.blobRef)
			if (err != nil) != tt.shouldErr {
				t.Fatalf("verifyBlob() error = %v, expected shouldErr = %t", err, tt.shouldErr)
			}
			if tt.expectedErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.expectedErr) {
					t.Fatalf("expected error containing %q, got: %v", tt.expectedErr, err)
				}
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
		KeyOpts: options.KeyOpts{
			BundlePath: "bundle.json",
		},
	}
	err := verifyBlob.Exec(ctx, "blob")
	if err == nil {
		t.Fatalf("verifyBlob() expected error for missing certificate identity")
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

func TestVerifyBlobSkWithoutIdentities(t *testing.T) {
	ctx := context.Background()
	verifyBlob := VerifyBlobCmd{
		KeyOpts: options.KeyOpts{
			Sk:         true,
			BundlePath: "bundle.sigstore.json",
		},
	}

	err := verifyBlob.Exec(ctx, "blob")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "opening piv token") {
		t.Fatalf("expected PIV error, got: %v", err)
	}
}

func TestVerifyBlobWithUnsetHashAlgorithmMatchesKeyDefault(t *testing.T) {
	ctx := context.Background()
	td := t.TempDir()

	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := signature.LoadECDSASignerVerifier(priv, crypto.SHA512)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := cryptoutils.MarshalPublicKeyToPEM(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := writeBlobFile(t, td, string(pubPEM), "key.pub")

	blob := "someblob"
	blobPath := writeBlobFile(t, td, blob, "blob.txt")

	digest := sha512.Sum512([]byte(blob))
	sig, err := signer.SignMessage(bytes.NewReader([]byte(blob)))
	if err != nil {
		t.Fatal(err)
	}

	bundlePath := makeLocalNewBundleWithAlgorithm(t, sig, digest[:], protocommon.HashAlgorithm_SHA2_512)

	cmd := VerifyBlobCmd{
		KeyOpts: options.KeyOpts{
			KeyRef:     keyPath,
			BundlePath: bundlePath,
		},
		IgnoreTlog: true,
	}
	if err := cmd.Exec(ctx, blobPath); err != nil {
		t.Fatalf("expected verification to succeed using P-521 key default hash algorithm (SHA512), got: %v", err)
	}

	// Negative test: verification fails with altered blob
	otherBlobPath := writeBlobFile(t, td, "differentblob", "other_blob.txt")
	if err := cmd.Exec(ctx, otherBlobPath); err == nil {
		t.Fatal("expected verification to fail with mismatched blob content, got nil")
	}
}

func makeLocalNewBundle(t *testing.T, sig []byte, digest [32]byte) string {
	return makeLocalNewBundleWithAlgorithm(t, sig, digest[:], protocommon.HashAlgorithm_SHA2_256)
}

func makeLocalNewBundleWithAlgorithm(t *testing.T, sig []byte, digest []byte, algo protocommon.HashAlgorithm) string {
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
				Algorithm: algo,
				Digest:    digest,
			},
			Signature: sig,
		},
	}

	contents, err := protojson.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}

	td := t.TempDir()
	bundlePath := filepath.Join(td, "bundle.sigstore.json")
	if err := os.WriteFile(bundlePath, contents, 0644); err != nil {
		t.Fatal(err)
	}
	return bundlePath
}

func writeBlobFile(t *testing.T, td string, blob string, name string) string {
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
