// Copyright 2024 The Sigstore Authors.
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

//go:build e2e && cross

package test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/attach"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/download"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	cliverify "github.com/sigstore/cosign/v2/cmd/cosign/cli/verify"
	"github.com/sigstore/cosign/v2/internal/pkg/cosign/tsa"
	"github.com/sigstore/cosign/v2/internal/pkg/cosign/tsa/client"
	cert_test "github.com/sigstore/cosign/v2/internal/test"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	tsaclient "github.com/sigstore/timestamp-authority/pkg/client"
	"github.com/sigstore/timestamp-authority/pkg/server"
	"github.com/spf13/viper"
)

func TestAttachSignature(t *testing.T) {
	ctx := context.Background()

	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "cosign-attach-e2e")

	imgRef, desc, cleanup := mkimage(t, imgName)
	defer cleanup()

	// Generate payload
	b := bytes.Buffer{}
	must(generate.GenerateCmd(context.Background(), options.RegistryOptions{}, imgName, nil, &b), t)
	payloadRef := mkfile(b.String(), td, t)
	hash := sha256.Sum256(b.Bytes())

	// Scenario 1: attach a single signature with certificate and certificate chain to an artifact
	// and verify it using the root certificate.
	rootCert1, rootKey1, _ := cert_test.GenerateRootCa()
	pemRoot1 := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert1.Raw})
	pemRootRef1 := mkfile(string(pemRoot1), td, t)
	subCert1, subKey1, _ := cert_test.GenerateSubordinateCa(rootCert1, rootKey1)
	leafCert1, privKey1, _ := cert_test.GenerateLeafCert("foo@example.com", "oidc-issuer", subCert1, subKey1)
	pemSub1 := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: subCert1.Raw})
	pemLeaf1 := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert1.Raw})
	pemLeafRef1 := mkfile(string(pemLeaf1), td, t)
	certChainRef1 := mkfile(string(append(pemSub1, pemRoot1...)), td, t)

	signature1, _ := privKey1.Sign(rand.Reader, hash[:], crypto.SHA256)
	b64signature1 := base64.StdEncoding.EncodeToString(signature1)
	sigRef1 := mkfile(b64signature1, td, t)

	err := attach.SignatureCmd(ctx, options.RegistryOptions{}, sigRef1, payloadRef, pemLeafRef1, certChainRef1, "", "", imgName)
	must(err, t)

	remoteSigRef, err := name.ParseReference(fmt.Sprintf("%s:sha256-%s.sig", imgRef, strings.Split(desc.Digest.String(), ":")[1]), name.WeakValidation)
	must(err, t)

	si, err := ociremote.SignedImage(remoteSigRef, ociremote.WithRemoteOptions(registryClientOpts(ctx)...))
	must(err, t)

	manifest, err := si.Manifest()
	must(err, t)

	equals(manifest.Config.MediaType, types.MediaType("application/vnd.oci.image.config.v1+json"), t)
	if len(manifest.Layers) != 1 {
		t.Fatal("expected exactly one layer")
	}
	_, certOk := manifest.Layers[0].Annotations["dev.sigstore.cosign/certificate"]
	equals(certOk, true, t)
	_, chainOk := manifest.Layers[0].Annotations["dev.sigstore.cosign/chain"]
	equals(chainOk, true, t)

	verifyCmd := cliverify.VerifyCommand{
		IgnoreSCT:  true,
		IgnoreTlog: true,
		CertChain:  pemRootRef1,
		CertVerifyOptions: options.CertVerifyOptions{
			CertOidcIssuerRegexp: ".*",
			CertIdentityRegexp:   ".*",
		},
	}
	args := []string{imgName}
	must(verifyCmd.Exec(ctx, args), t)

	// Scenario 2: Attaches second signature with another certificate and  certificate chain to the
	// same artifact and verify it using both root certificates separately.
	rootCert2, rootKey2, _ := cert_test.GenerateRootCa()
	pemRoot2 := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert2.Raw})
	pemRootRef2 := mkfile(string(pemRoot2), td, t)
	subCert2, subKey2, _ := cert_test.GenerateSubordinateCa(rootCert2, rootKey2)
	leafCert2, privKey2, _ := cert_test.GenerateLeafCert("foo@exampleclient.com", "oidc-issuer", subCert2, subKey2)
	pemSub2 := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: subCert2.Raw})
	pemLeaf2 := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert2.Raw})
	pemLeafRef2 := mkfile(string(pemLeaf2), td, t)
	certChainRef2 := mkfile(string(append(pemSub2, pemRoot2...)), td, t)

	signature2, _ := privKey2.Sign(rand.Reader, hash[:], crypto.SHA256)
	b64signature2 := base64.StdEncoding.EncodeToString(signature2)
	sigRef2 := mkfile(b64signature2, td, t)

	err = attach.SignatureCmd(ctx, options.RegistryOptions{}, sigRef2, payloadRef, pemLeafRef2, certChainRef2, "", "", imgName)
	must(err, t)

	// verify using first root certificate
	verifyCmd = cliverify.VerifyCommand{
		IgnoreSCT:  true,
		IgnoreTlog: true,
		CertChain:  pemRootRef1,
		CertVerifyOptions: options.CertVerifyOptions{
			CertOidcIssuerRegexp: ".*",
			CertIdentityRegexp:   ".*",
		},
	}
	args = []string{imgName}
	must(verifyCmd.Exec(ctx, args), t)

	// verify using second root cert
	verifyCmd = cliverify.VerifyCommand{
		IgnoreSCT:  true,
		IgnoreTlog: true,
		CertChain:  pemRootRef2,
		CertVerifyOptions: options.CertVerifyOptions{
			CertOidcIssuerRegexp: ".*",
			CertIdentityRegexp:   ".*",
		},
	}
	args = []string{imgName}
	must(verifyCmd.Exec(ctx, args), t)
}

func TestAttachWithRFC3161Timestamp(t *testing.T) {
	ctx := context.Background()
	// TSA server needed to create timestamp
	viper.Set("timestamp-signer", "memory")
	viper.Set("timestamp-signer-hash", "sha256")
	apiServer := server.NewRestAPIServer("localhost", 0, []string{"http"}, false, 10*time.Second, 10*time.Second)
	server := httptest.NewServer(apiServer.GetHandler())
	t.Cleanup(server.Close)

	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "cosign-attach-timestamp-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	b := bytes.Buffer{}
	must(generate.GenerateCmd(context.Background(), options.RegistryOptions{}, imgName, nil, &b), t)

	rootCert, rootKey, _ := cert_test.GenerateRootCa()
	subCert, subKey, _ := cert_test.GenerateSubordinateCa(rootCert, rootKey)
	leafCert, privKey, _ := cert_test.GenerateLeafCert("subject@mail.com", "oidc-issuer", subCert, subKey)
	pemRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Raw})
	pemSub := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: subCert.Raw})
	pemLeaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Raw})

	payloadref := mkfile(b.String(), td, t)

	h := sha256.Sum256(b.Bytes())
	signature, _ := privKey.Sign(rand.Reader, h[:], crypto.SHA256)
	b64signature := base64.StdEncoding.EncodeToString(signature)
	sigRef := mkfile(b64signature, td, t)
	pemleafRef := mkfile(string(pemLeaf), td, t)
	pemrootRef := mkfile(string(pemRoot), td, t)

	certchainRef := mkfile(string(append(pemSub, pemRoot...)), td, t)

	t.Setenv("SIGSTORE_ROOT_FILE", pemrootRef)

	tsclient, err := tsaclient.GetTimestampClient(server.URL)
	if err != nil {
		t.Error(err)
	}

	chain, err := tsclient.Timestamp.GetTimestampCertChain(nil)
	if err != nil {
		t.Fatalf("unexpected error getting timestamp chain: %v", err)
	}

	file, err := os.CreateTemp(os.TempDir(), "tempfile")
	if err != nil {
		t.Fatalf("error creating temp file: %v", err)
	}
	defer os.Remove(file.Name())
	_, err = file.WriteString(chain.Payload)
	if err != nil {
		t.Fatalf("error writing chain payload to temp file: %v", err)
	}

	tsBytes, err := tsa.GetTimestampedSignature(signature, client.NewTSAClient(server.URL+"/api/v1/timestamp"))
	if err != nil {
		t.Fatalf("unexpected error creating timestamp: %v", err)
	}
	rfc3161TSRef := mkfile(string(tsBytes), td, t)

	// Upload it!
	err = attach.SignatureCmd(ctx, options.RegistryOptions{}, sigRef, payloadref, pemleafRef, certchainRef, rfc3161TSRef, "", imgName)
	if err != nil {
		t.Fatal(err)
	}

	must(verifyKeylessTSA(imgName, file.Name(), true, true), t)
}

func TestAttachWithRekorBundle(t *testing.T) {
	ctx := context.Background()

	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "cosign-attach-timestamp-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	b := bytes.Buffer{}
	must(generate.GenerateCmd(context.Background(), options.RegistryOptions{}, imgName, nil, &b), t)

	rootCert, rootKey, _ := cert_test.GenerateRootCa()
	subCert, subKey, _ := cert_test.GenerateSubordinateCa(rootCert, rootKey)
	leafCert, privKey, _ := cert_test.GenerateLeafCert("subject@mail.com", "oidc-issuer", subCert, subKey)
	pemRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Raw})
	pemSub := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: subCert.Raw})
	pemLeaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Raw})

	payloadref := mkfile(b.String(), td, t)

	h := sha256.Sum256(b.Bytes())
	signature, _ := privKey.Sign(rand.Reader, h[:], crypto.SHA256)
	b64signature := base64.StdEncoding.EncodeToString(signature)
	sigRef := mkfile(b64signature, td, t)
	pemleafRef := mkfile(string(pemLeaf), td, t)
	pemrootRef := mkfile(string(pemRoot), td, t)

	t.Setenv("SIGSTORE_ROOT_FILE", pemrootRef)

	certchainRef := mkfile(string(append(pemSub, pemRoot...)), td, t)

	localPayload := cosign.LocalSignedPayload{
		Base64Signature: b64signature,
		Cert:            string(pemLeaf),
		Bundle: &bundle.RekorBundle{
			SignedEntryTimestamp: strfmt.Base64("MEUCIEDcarEwRYkrxE9ne+kzEVvUhnWaauYzxhUyXOLy1hwAAiEA4VdVCvNRs+D/5o33C2KBy+q2YX3lP4Y7nqRFU+K3hi0="),
			Payload: bundle.RekorPayload{
				Body:           "REMOVED",
				IntegratedTime: 1631646761,
				LogIndex:       693591,
				LogID:          "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
			},
		},
	}

	jsonBundle, err := json.Marshal(localPayload)
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(td, "bundle.json")
	if err := os.WriteFile(bundlePath, jsonBundle, 0644); err != nil {
		t.Fatal(err)
	}

	// Upload it!
	err = attach.SignatureCmd(ctx, options.RegistryOptions{}, sigRef, payloadref, pemleafRef, certchainRef, "", bundlePath, imgName)
	if err != nil {
		t.Fatal(err)
	}
}

func TestUploadDownload(t *testing.T) {
	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()
	ctx := context.Background()

	testCases := map[string]struct {
		signature     string
		signatureType attach.SignatureArgType
		expectedErr   bool
	}{
		"stdin containing signature": {
			signature:     "testsignatureraw",
			signatureType: attach.StdinSignature,
			expectedErr:   false,
		},
		"file containing signature": {
			signature:     "testsignaturefile",
			signatureType: attach.FileSignature,
			expectedErr:   false,
		},
		"raw signature as argument": {
			signature:     "testsignatureraw",
			signatureType: attach.RawSignature,
			expectedErr:   true,
		},
		"empty signature as argument": {
			signature:     "",
			signatureType: attach.RawSignature,
			expectedErr:   true,
		},
	}

	imgName := path.Join(repo, "cosign-e2e")
	for testName, testCase := range testCases {
		t.Run(testName, func(t *testing.T) {
			ref, _, cleanup := mkimage(t, imgName)
			payload := "testpayload"
			payloadPath := mkfile(payload, td, t)
			signature := base64.StdEncoding.EncodeToString([]byte(testCase.signature))
			restoreStdin := func() {}

			var sigRef string
			switch {
			case testCase.signatureType == attach.FileSignature:
				sigRef = mkfile(signature, td, t)
			case testCase.signatureType == attach.StdinSignature:
				sigRef = mkfile(signature, td, t)
			default:
				sigRef = signature
			}
			// Upload it!
			err := attach.SignatureCmd(ctx, options.RegistryOptions{}, sigRef, payloadPath, "", "", "", "", imgName)
			if testCase.expectedErr {
				mustErr(err, t)
			} else {
				must(err, t)
			}
			restoreStdin()

			// Now download it!
			se, err := ociremote.SignedEntity(ref, ociremote.WithRemoteOptions(registryClientOpts(ctx)...))
			must(err, t)
			sigs, err := se.Signatures()
			must(err, t)
			signatures, err := sigs.Get()
			must(err, t)

			if testCase.expectedErr {
				if len(signatures) != 0 {
					t.Fatalf("unexpected signatures %d, wanted 0", len(signatures))
				}
			} else {
				if len(signatures) != 1 {
					t.Fatalf("unexpected signatures %d, wanted 1", len(signatures))
				}

				if b64sig, err := signatures[0].Base64Signature(); err != nil {
					t.Fatalf("Base64Signature() = %v", err)
				} else if diff := cmp.Diff(b64sig, signature); diff != "" {
					t.Error(diff)
				}

				if p, err := signatures[0].Payload(); err != nil {
					t.Fatalf("Payload() = %v", err)
				} else if diff := cmp.Diff(p, []byte(payload)); diff != "" {
					t.Error(diff)
				}
			}

			// Now delete it!
			cleanup()
		})
	}
}

func TestAttachSBOM_bom_flag(t *testing.T) {
	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()
	ctx := context.Background()
	bomData, err := os.ReadFile("./testdata/bom-go-mod.spdx")
	must(err, t)

	testCases := map[string]struct {
		bom         string
		bomType     attach.SignatureArgType
		expectedErr bool
	}{
		"stdin containing bom": {
			bom:         string(bomData),
			bomType:     attach.StdinSignature,
			expectedErr: false,
		},
		"file containing bom": {
			bom:         string(bomData),
			bomType:     attach.FileSignature,
			expectedErr: false,
		},
		"raw bom as argument": {
			bom:         string(bomData),
			bomType:     attach.RawSignature,
			expectedErr: true,
		},
		"empty bom as argument": {
			bom:         "",
			bomType:     attach.RawSignature,
			expectedErr: true,
		},
	}

	for testName, testCase := range testCases {
		t.Run(testName, func(t *testing.T) {
			imgName := path.Join(repo, "sbom-image")
			img, _, cleanup := mkimage(t, imgName)
			var sbomRef string
			restoreStdin := func() {}
			switch {
			case testCase.bomType == attach.FileSignature:
				sbomRef = mkfile(testCase.bom, td, t)
			case testCase.bomType == attach.StdinSignature:
				sbomRef = "-"
				restoreStdin = mockStdin(testCase.bom, td, t)
			default:
				sbomRef = testCase.bom
			}

			out := bytes.Buffer{}
			_, errPl := download.SBOMCmd(ctx, options.RegistryOptions{}, options.SBOMDownloadOptions{Platform: "darwin/amd64"}, img.Name(), &out)
			if errPl == nil {
				t.Fatalf("Expected error when passing Platform to single arch image")
			}
			_, err := download.SBOMCmd(ctx, options.RegistryOptions{}, options.SBOMDownloadOptions{}, img.Name(), &out)
			if err == nil {
				t.Fatal("Expected error")
			}
			t.Log(out.String())
			out.Reset()

			// Upload it!
			err = attach.SBOMCmd(ctx, options.RegistryOptions{}, options.RegistryExperimentalOptions{}, sbomRef, "spdx", imgName)
			restoreStdin()

			if testCase.expectedErr {
				mustErr(err, t)
			} else {
				sboms, err := download.SBOMCmd(ctx, options.RegistryOptions{}, options.SBOMDownloadOptions{}, imgName, &out)
				if err != nil {
					t.Fatal(err)
				}
				t.Log(out.String())
				if len(sboms) != 1 {
					t.Fatalf("Expected one sbom, got %d", len(sboms))
				}
				want, err := os.ReadFile("./testdata/bom-go-mod.spdx")
				if err != nil {
					t.Fatal(err)
				}
				if diff := cmp.Diff(string(want), sboms[0]); diff != "" {
					t.Errorf("diff: %s", diff)
				}
			}

			cleanup()
		})
	}
}
