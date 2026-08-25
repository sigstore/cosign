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

package signcommon

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/secure-systems-lab/go-securesystemslib/encrypted"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/sign/privacy"
	"github.com/sigstore/cosign/v3/internal/test"
	"github.com/sigstore/cosign/v3/internal/ui"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	pb_go_v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/stretchr/testify/assert"
)

func pass(s string) cosign.PassFunc {
	return func(_ bool) ([]byte, error) {
		return []byte(s), nil
	}
}

func generateCertificateFiles(t *testing.T, tmpDir string, pf cosign.PassFunc) (privFile, certFile, chainFile string, privKey *ecdsa.PrivateKey, cert *x509.Certificate, chain []*x509.Certificate) {
	t.Helper()

	rootCert, rootKey, _ := test.GenerateRootCa()
	subCert, subKey, _ := test.GenerateSubordinateCa(rootCert, rootKey)
	leafCert, privKey, _ := test.GenerateLeafCert("subject", "oidc-issuer", subCert, subKey)
	pemRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Raw})
	pemSub := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: subCert.Raw})
	pemLeaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Raw})

	x509Encoded, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		t.Fatalf("failed to encode private key: %v", err)
	}
	password := []byte{}
	if pf != nil {
		password, err = pf(true)
		if err != nil {
			t.Fatalf("failed to read password: %v", err)
		}
	}

	encBytes, err := encrypted.Encrypt(x509Encoded, password)
	if err != nil {
		t.Fatalf("failed to encrypt key: %v", err)
	}

	// store in PEM format
	privBytes := pem.EncodeToMemory(&pem.Block{
		Bytes: encBytes,
		Type:  cosign.CosignPrivateKeyPemType,
	})

	tmpPrivFile, err := os.CreateTemp(tmpDir, "cosign_test_*.key")
	if err != nil {
		t.Fatalf("failed to create temp key file: %v", err)
	}
	defer tmpPrivFile.Close()
	if _, err := tmpPrivFile.Write(privBytes); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	tmpCertFile, err := os.CreateTemp(tmpDir, "cosign.crt")
	if err != nil {
		t.Fatalf("failed to create temp certificate file: %v", err)
	}
	defer tmpCertFile.Close()
	if _, err := tmpCertFile.Write(pemLeaf); err != nil {
		t.Fatalf("failed to write certificate file: %v", err)
	}

	tmpChainFile, err := os.CreateTemp(tmpDir, "cosign_chain.crt")
	if err != nil {
		t.Fatalf("failed to create temp chain file: %v", err)
	}
	defer tmpChainFile.Close()
	pemChain := pemSub
	pemChain = append(pemChain, pemRoot...)
	if _, err := tmpChainFile.Write(pemChain); err != nil {
		t.Fatalf("failed to write chain file: %v", err)
	}

	return tmpPrivFile.Name(), tmpCertFile.Name(), tmpChainFile.Name(), privKey, leafCert, []*x509.Certificate{subCert, rootCert}
}

func Test_signerFromKeyRefSuccess(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()
	keyFile, certFile, chainFile, privKey, cert, chain := generateCertificateFiles(t, tmpDir, pass("foo"))

	signer, err := signerFromKeyRef(ctx, certFile, chainFile, keyFile, pass("foo"), nil)
	if err != nil {
		t.Fatalf("unexpected error generating signer: %v", err)
	}
	// Expect public key matches
	pubKey, err := signer.PublicKey()
	if err != nil {
		t.Fatalf("unexpected error fetching pubkey: %v", err)
	}
	if !privKey.Public().(*ecdsa.PublicKey).Equal(pubKey) {
		t.Fatalf("public keys must be equal")
	}
	// Expect certificate matches
	expectedPemBytes, err := cryptoutils.MarshalCertificateToPEM(cert)
	if err != nil {
		t.Fatalf("unexpected error marshalling certificate: %v", err)
	}
	if !reflect.DeepEqual(signer.Cert, expectedPemBytes) {
		t.Fatalf("certificates must match")
	}
	// Expect certificate chain matches
	expectedPemBytesChain, err := cryptoutils.MarshalCertificatesToPEM(chain)
	if err != nil {
		t.Fatalf("unexpected error marshalling certificate chain: %v", err)
	}
	if !reflect.DeepEqual(signer.Chain, expectedPemBytesChain) {
		t.Fatalf("certificate chains must match")
	}
}

func Test_signerFromKeyRefFailure(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()
	keyFile, certFile, _, _, _, _ := generateCertificateFiles(t, tmpDir, pass("foo"))
	// Second set of files
	tmpDir2 := t.TempDir()
	_, certFile2, chainFile2, _, _, _ := generateCertificateFiles(t, tmpDir2, pass("bar"))

	// Public keys don't match
	_, err := signerFromKeyRef(ctx, certFile2, chainFile2, keyFile, pass("foo"), nil)
	if err == nil || err.Error() != "public key in certificate does not match the provided public key" {
		t.Fatalf("expected mismatched keys error, got %v", err)
	}
	// Certificate chain cannot be verified
	_, err = signerFromKeyRef(ctx, certFile, chainFile2, keyFile, pass("foo"), nil)
	if err == nil || !strings.Contains(err.Error(), "unable to validate certificate chain") {
		t.Fatalf("expected chain verification error, got %v", err)
	}
	// Certificate chain specified without certificate
	_, err = signerFromKeyRef(ctx, "", chainFile2, keyFile, pass("foo"), nil)
	if err == nil || !strings.Contains(err.Error(), "no leaf certificate found or provided while specifying chain") {
		t.Fatalf("expected no leaf error, got %v", err)
	}
}

func Test_signerFromKeyRefFailureEmptyChainFile(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()
	keyFile, certFile, _, _, _, _ := generateCertificateFiles(t, tmpDir, pass("foo"))

	tmpChainFile, err := os.CreateTemp(tmpDir, "cosign_chain_empty.crt")
	if err != nil {
		t.Fatalf("failed to create temp chain file: %v", err)
	}
	defer tmpChainFile.Close()
	if _, err := tmpChainFile.Write([]byte{}); err != nil {
		t.Fatalf("failed to write chain file: %v", err)
	}

	_, err = signerFromKeyRef(ctx, certFile, tmpChainFile.Name(), keyFile, pass("foo"), nil)
	if err == nil || err.Error() != "no certificates in certificate chain" {
		t.Fatalf("expected empty chain error, got %v", err)
	}
}

func Test_ParseOCIReference(t *testing.T) {
	var tests = []struct {
		ref             string
		expectedWarning string
	}{
		{"image:bytag", "WARNING: Image reference image:bytag uses a tag, not a digest"},
		{"image:bytag@sha256:abcdef", ""},
		{"image:@sha256:abcdef", ""},
	}
	for _, tt := range tests {
		stderr := ui.RunWithTestCtx(func(ctx context.Context, _ ui.WriteFunc) {
			ParseOCIReference(ctx, tt.ref)
		})
		if len(tt.expectedWarning) > 0 {
			assert.Contains(t, stderr, tt.expectedWarning, stderr, "bad warning message")
		} else {
			assert.Empty(t, stderr, "expected no warning")
		}
	}
}

func mustSigningConfig(t *testing.T, rekorURL string) *root.SigningConfig {
	t.Helper()
	sc, err := NewSigningConfigFromKeyOpts(options.KeyOpts{RekorURL: rekorURL})
	if err != nil {
		t.Fatalf("creating signing config: %v", err)
	}
	return sc
}

func TestShouldUploadToTlog_PublicInstanceStatement(t *testing.T) {
	tests := []struct {
		name          string
		signingConfig *root.SigningConfig
		wantWarning   bool
	}{
		{"custom Rekor URL skips public instance statement", mustSigningConfig(t, "http://localhost:3000"), false},
		{"region-specific public good URL shows public instance statement", mustSigningConfig(t, "https://rekor.us-central1.sigstore.dev"), true},
		{"staging public good signing config shows public instance statement", mustSigningConfig(t, "https://rekor.sigstage.dev"), true},
		{"nil signing config skips public instance statement", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privacy.StatementOnce = sync.Once{}
			ko := options.KeyOpts{
				SigningConfig:    tt.signingConfig,
				SkipConfirmation: true,
			}
			var upload bool
			var err error
			stderr := ui.RunWithTestCtx(func(ctx context.Context, _ ui.WriteFunc) {
				upload, err = ShouldUploadToTlog(ctx, ko, nil, true)
			})
			assert.NoError(t, err)
			assert.True(t, upload)
			if tt.wantWarning {
				assert.Contains(t, stderr, "hosted by sigstore", "should warn about the public good instance's data retention policy")
			} else {
				assert.NotContains(t, stderr, "hosted by sigstore", "should not warn about the public good instance's data retention policy")
			}
		})
	}
}

func TestShouldUploadToTlog(t *testing.T) {
	tests := []struct {
		name          string
		signingConfig *root.SigningConfig
		tlogUpload    bool
		wantUpload    bool
	}{
		{
			name:          "tlogUpload false returns false",
			signingConfig: mustSigningConfig(t, options.DefaultRekorURL),
			tlogUpload:    false,
			wantUpload:    false,
		},
		{
			name:          "signing config with no Rekor URLs returns false",
			signingConfig: mustSigningConfig(t, options.DefaultRekorURL).WithRekorLogURLs(),
			tlogUpload:    true,
			wantUpload:    false,
		},
		{
			name:          "tlogUpload true with Rekor URL returns true",
			signingConfig: mustSigningConfig(t, "http://localhost:3000"),
			tlogUpload:    true,
			wantUpload:    true,
		},
		{
			name:          "nil signing config with tlogUpload true returns true",
			signingConfig: nil,
			tlogUpload:    true,
			wantUpload:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ko := options.KeyOpts{
				SigningConfig:    tt.signingConfig,
				SkipConfirmation: true,
			}
			upload, err := ShouldUploadToTlog(context.Background(), ko, nil, tt.tlogUpload)
			assert.NoError(t, err)
			assert.Equal(t, tt.wantUpload, upload)
		})
	}
}

func TestHasPublicGoodRekorURL(t *testing.T) {
	tests := []struct {
		name          string
		signingConfig *root.SigningConfig
		want          bool
	}{
		{"nil signing config returns false", nil, false},
		{"empty signing config returns false", mustSigningConfig(t, ""), false},
		{"custom Rekor URL returns false", mustSigningConfig(t, "http://localhost:3000"), false},
		{"public good Rekor URL returns true", mustSigningConfig(t, options.DefaultRekorURL), true},
		{"signing config with cleared Rekor URLs returns false", mustSigningConfig(t, options.DefaultRekorURL).WithRekorLogURLs(), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, hasPublicGoodRekorURL(tt.signingConfig))
		})
	}
}

func TestIsPublicGoodRekorURL(t *testing.T) {
	tests := []struct {
		name     string
		rekorURL string
		want     bool
	}{
		{"empty is not public good", "", false},
		{"default production URL", options.DefaultRekorURL, true},
		{"region-specific production URL", "https://rekor.us-central1.sigstore.dev", true},
		{"staging URL", "https://rekor.sigstage.dev", true},
		{"region-specific staging URL", "https://rekor.us-central1.sigstage.dev", true},
		{"custom self-hosted URL", "http://localhost:3000", false},
		{"uppercase hostname is still public good", "https://REKOR.SIGSTORE.DEV", true},
		{"lookalike domain is not public good", "https://sigstore.dev.evil.example.com", false},
		{"lookalike suffix without dot boundary is not public good", "https://notsigstore.dev", false},
		{"unparseable URL", "://bad-url", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isPublicGoodRekorURL(tt.rekorURL))
		})
	}
}

func TestNewLegacyBundleFromProtoBundleComponents(t *testing.T) {
	t.Run("without certificates leaves cert field empty", func(t *testing.T) {
		bc := &BundleComponents{
			Signature: []byte("signature"),
		}
		bundleBytes, err := NewLegacyBundleFromProtoBundleComponents(bc)
		assert.NoError(t, err)

		var payload cosign.LocalSignedPayload
		err = json.Unmarshal(bundleBytes, &payload)
		assert.NoError(t, err)
		assert.Empty(t, payload.Cert, "expected empty cert field when BundleComponents has no certificates")
	})

	t.Run("with certificates populates cert field", func(t *testing.T) {
		rootCert, _, _ := test.GenerateRootCa()
		bc := &BundleComponents{
			Signature:    []byte("signature"),
			Certificates: []*pb_go_v1.X509Certificate{{RawBytes: rootCert.Raw}},
		}
		bundleBytes, err := NewLegacyBundleFromProtoBundleComponents(bc)
		assert.NoError(t, err)

		var payload cosign.LocalSignedPayload
		err = json.Unmarshal(bundleBytes, &payload)
		assert.NoError(t, err)
		assert.NotEmpty(t, payload.Cert, "expected non-empty cert field when BundleComponents has certificates")
	})
}

func TestValidateSigningOptions(t *testing.T) {
	tests := []struct {
		name              string
		offline           bool
		rekorURL          string
		fulcioURL         string
		oidcIssuer        string
		tsaServerURL      string
		tlogUpload        bool
		newBundleFormat   bool
		bundlePath        string
		keyRef            string
		issueCertificate  bool
		output            string
		outputAttestation string
		outputCertificate string
		outputPayload     string
		outputSignature   string
		outputTimestamp   string
		wantErr           bool
		wantErrSubstr     string
		wantWarningSubstr string
	}{
		{
			name:            "valid default online signing flags",
			offline:         false,
			rekorURL:        options.DefaultRekorURL,
			fulcioURL:       options.DefaultFulcioURL,
			oidcIssuer:      options.DefaultOIDCIssuerURL,
			tlogUpload:      true,
			newBundleFormat: true,
			wantErr:         false,
		},
		{
			name:            "valid offline signing flags",
			offline:         true,
			keyRef:          "cosign.key",
			tlogUpload:      false,
			newBundleFormat: true,
			wantErr:         false,
		},
		{
			name:          "offline missing key",
			offline:       true,
			keyRef:        "",
			wantErr:       true,
			wantErrSubstr: "offline signing requires a private key",
		},
		{
			name:             "offline with issue certificate",
			offline:          true,
			keyRef:           "cosign.key",
			issueCertificate: true,
			wantErr:          true,
			wantErrSubstr:    "cannot issue certificate when offline",
		},
		{
			name:          "offline with custom service URLs",
			offline:       true,
			keyRef:        "cosign.key",
			rekorURL:      "http://localhost:3000",
			wantErr:       true,
			wantErrSubstr: "cannot specify service URLs when signing offline",
		},
		{
			name:          "online with custom rekor URL",
			offline:       false,
			rekorURL:      "http://localhost:3000",
			tlogUpload:    true,
			wantErr:       true,
			wantErrSubstr: "cannot specify service URLs when using a signing config",
		},
		{
			name:          "online with custom fulcio URL",
			offline:       false,
			fulcioURL:     "http://localhost:5555",
			tlogUpload:    true,
			wantErr:       true,
			wantErrSubstr: "cannot specify service URLs when using a signing config",
		},
		{
			name:          "online with custom OIDC issuer",
			offline:       false,
			oidcIssuer:    "http://localhost:8080",
			tlogUpload:    true,
			wantErr:       true,
			wantErrSubstr: "cannot specify service URLs when using a signing config",
		},
		{
			name:          "online with custom TSA server URL",
			offline:       false,
			tsaServerURL:  "http://localhost:3001",
			tlogUpload:    true,
			wantErr:       true,
			wantErrSubstr: "cannot specify service URLs when using a signing config",
		},
		{
			name:            "online with tlog upload false without offline",
			offline:         false,
			rekorURL:        options.DefaultRekorURL,
			fulcioURL:       options.DefaultFulcioURL,
			oidcIssuer:      options.DefaultOIDCIssuerURL,
			tlogUpload:      false,
			newBundleFormat: true,
			wantErr:         true,
			wantErrSubstr:   "--tlog-upload=false is not supported with a signing config",
		},
		{
			name:            "missing bundle output with signing config",
			offline:         false,
			rekorURL:        options.DefaultRekorURL,
			fulcioURL:       options.DefaultFulcioURL,
			oidcIssuer:      options.DefaultOIDCIssuerURL,
			tlogUpload:      true,
			newBundleFormat: false,
			bundlePath:      "",
			wantErr:         true,
			wantErrSubstr:   "must provide --new-bundle-format or --bundle",
		},
		{
			name:            "legacy bundle format with explicit bundle path is valid",
			offline:         false,
			rekorURL:        options.DefaultRekorURL,
			fulcioURL:       options.DefaultFulcioURL,
			oidcIssuer:      options.DefaultOIDCIssuerURL,
			tlogUpload:      true,
			newBundleFormat: false,
			bundlePath:      "/tmp/bundle.json",
			wantErr:         false,
		},
		{
			name:              "deprecated output-signature warning with new bundle format",
			newBundleFormat:   true,
			tlogUpload:        true,
			outputSignature:   "sig.sig",
			wantWarningSubstr: "--output-signature is deprecated when using --new-bundle-format",
		},
		{
			name:              "deprecated output-attestation warning with new bundle format",
			newBundleFormat:   true,
			tlogUpload:        true,
			outputAttestation: "att.att",
			wantWarningSubstr: "--output-attestation is deprecated when using --new-bundle-format",
		},
		{
			name:              "deprecated output-certificate warning with new bundle format",
			newBundleFormat:   true,
			tlogUpload:        true,
			outputCertificate: "cert.crt",
			wantWarningSubstr: "--output-certificate is deprecated when using --new-bundle-format",
		},
		{
			name:              "deprecated output-payload warning with new bundle format",
			newBundleFormat:   true,
			tlogUpload:        true,
			outputPayload:     "payload.json",
			wantWarningSubstr: "--output-payload is deprecated when using --new-bundle-format",
		},
		{
			name:              "deprecated rfc3161-timestamp warning with new bundle format",
			newBundleFormat:   true,
			tlogUpload:        true,
			outputTimestamp:   "ts.tsr",
			wantWarningSubstr: "--rfc3161-timestamp is deprecated when using --new-bundle-format",
		},
		{
			name:              "deprecated output warning with new bundle format",
			newBundleFormat:   true,
			tlogUpload:        true,
			output:            "out.sig",
			wantWarningSubstr: "--output is deprecated when using --new-bundle-format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			stderr := ui.RunWithTestCtx(func(ctx context.Context, _ ui.WriteFunc) {
				err = ValidateSigningOptions(ctx, tt.offline,
					tt.rekorURL, tt.fulcioURL, tt.oidcIssuer, tt.tsaServerURL,
					tt.tlogUpload, tt.newBundleFormat, tt.bundlePath, tt.keyRef, tt.issueCertificate,
					tt.output, tt.outputAttestation, tt.outputCertificate, tt.outputPayload, tt.outputSignature, tt.outputTimestamp)
			})
			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrSubstr != "" {
					assert.Contains(t, err.Error(), tt.wantErrSubstr)
				}
			} else {
				assert.NoError(t, err)
			}
			if tt.wantWarningSubstr != "" {
				assert.Contains(t, stderr, tt.wantWarningSubstr)
			}
		})
	}
}

func TestLoadTrustedMaterialAndSigningConfig(t *testing.T) {
	ctx := t.Context()

	t.Run("offline signing bypasses TUF and sets empty signing config", func(t *testing.T) {
		tufDir := t.TempDir()
		t.Setenv("TUF_ROOT", tufDir)
		t.Setenv("TUF_MIRROR", tufDir)

		var ko options.KeyOpts
		err := LoadTrustedMaterialAndSigningConfig(ctx, &ko, true, "", "")
		assert.NoError(t, err)
		assert.NotNil(t, ko.SigningConfig)
		assert.Nil(t, ko.TrustedMaterial)

		// Verify TUF directory remained empty and was not populated
		entries, err := os.ReadDir(tufDir)
		assert.NoError(t, err)
		assert.Empty(t, entries, "expected TUF directory to remain empty when signing offline")
	})

	t.Run("online signing attempts to contact TUF and fails when mirror is invalid", func(t *testing.T) {
		tufDir := t.TempDir()
		t.Setenv("TUF_ROOT", tufDir)
		t.Setenv("TUF_MIRROR", tufDir)

		var ko options.KeyOpts
		var err error
		_ = ui.RunWithTestCtx(func(ctx context.Context, _ ui.WriteFunc) {
			err = LoadTrustedMaterialAndSigningConfig(ctx, &ko, false, "", "")
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "error getting signing config from TUF")
	})
}
