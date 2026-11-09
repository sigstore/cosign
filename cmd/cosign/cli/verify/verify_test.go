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
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/v3/internal/pkg/cosign/fulcio/fulcioroots"
	"github.com/sigstore/cosign/v3/internal/test"
	"github.com/sigstore/cosign/v3/internal/ui"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	"github.com/sigstore/sigstore/pkg/signature/payload"
	"github.com/stretchr/testify/assert"
)

type certData struct {
	RootCert    *x509.Certificate
	RootKey     *ecdsa.PrivateKey
	SubCert     *x509.Certificate
	SubKey      *ecdsa.PrivateKey
	LeafCert    *x509.Certificate
	PrivKey     *ecdsa.PrivateKey
	RootCertPEM []byte
	SubCertPEM  []byte
	LeafCertPEM []byte
}

func getTestCerts(t *testing.T) *certData {
	t.Helper()
	eexts := []pkix.Extension{
		{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 2}, Value: []byte("myWorkflowTrigger")},
		{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 3}, Value: []byte("myWorkflowSha")},
		{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 4}, Value: []byte("myWorkflowName")},
		{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 5}, Value: []byte("myWorkflowRepository")},
		{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 6}, Value: []byte("myWorkflowRef")},
	}
	cd := &certData{}
	var err error
	if cd.RootCert, cd.RootKey, err = test.GenerateRootCa(); err != nil {
		t.Fatal(err)
	}
	if cd.SubCert, cd.SubKey, err = test.GenerateSubordinateCa(cd.RootCert, cd.RootKey); err != nil {
		t.Fatal(err)
	}
	if cd.LeafCert, cd.PrivKey, err = test.GenerateLeafCert("subject", "oidc-issuer", cd.SubCert, cd.SubKey, eexts...); err != nil {
		t.Fatal(err)
	}
	cd.RootCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cd.RootCert.Raw})
	cd.SubCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cd.SubCert.Raw})
	cd.LeafCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cd.LeafCert.Raw})
	return cd
}

func makeCertChainFile(t *testing.T, rootCert, subCert, leafCert []byte) string {
	t.Helper()
	f, err := os.CreateTemp("", "certchain")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	_, err = f.Write(append(append(rootCert, subCert...), leafCert...))
	if err != nil {
		t.Fatal(err)
	}
	return f.Name()
}

func makeRootsIntermediatesFiles(t *testing.T, roots, intermediates []byte) (string, string) {
	t.Helper()
	rootF, err := os.CreateTemp("", "roots")
	if err != nil {
		t.Fatal(err)
	}
	defer rootF.Close()
	_, err = rootF.Write(roots)
	if err != nil {
		t.Fatal(err)
	}
	intermediateF, err := os.CreateTemp("", "intermediates")
	if err != nil {
		t.Fatal(err)
	}
	defer intermediateF.Close()
	_, err = intermediateF.Write(intermediates)
	if err != nil {
		t.Fatal(err)
	}
	return rootF.Name(), intermediateF.Name()
}

func TestPrintVerification(t *testing.T) {
	// while we are adding a more human-readable output for cert extensions, on the other hand
	// we want as backward compatible as possible, so we are keeping the old OIDs field names as well.
	wantPayload := `
[
    {
        "critical": {
            "identity": {
                "docker-reference": "gcr.io/baz/baz"
            },
            "image": {
                "docker-manifest-digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            },
            "type": "cosign container image signature"
        },
        "optional": {
            "1.3.6.1.4.1.57264.1.1": "oidc-issuer",
            "1.3.6.1.4.1.57264.1.2": "myWorkflowTrigger",
            "1.3.6.1.4.1.57264.1.3": "myWorkflowSha",
            "1.3.6.1.4.1.57264.1.4": "myWorkflowName",
            "1.3.6.1.4.1.57264.1.5": "myWorkflowRepository",
            "1.3.6.1.4.1.57264.1.6": "myWorkflowRef",
            "Issuer": "oidc-issuer",
            "Subject": "subject",
            "githubWorkflowName": "myWorkflowName",
            "githubWorkflowRef": "myWorkflowRef",
            "githubWorkflowRepository": "myWorkflowRepository",
            "githubWorkflowSha": "myWorkflowSha",
            "githubWorkflowTrigger": "myWorkflowTrigger"
        }
    }
]
`
	certs := getTestCerts(t)
	rootPool := x509.NewCertPool()
	rootPool.AddCert(certs.RootCert)

	// Generate the payload for the image, and check the digest.
	b := bytes.Buffer{}
	dig3, err := name.NewDigest("gcr.io/baz/baz@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", name.StrictValidation)
	if err != nil {
		t.Fatalf("Error creating test dig3.")
	}
	pp, err := (&payload.Cosign{Image: dig3, Annotations: map[string]interface{}{}}).MarshalJSON()
	if err != nil {
		t.Fatalf("Error creating cosign payload")
	}
	fmt.Fprintln(&b, string(pp))

	p := b.Bytes()
	h := sha256.Sum256(p)
	signature, _ := certs.PrivKey.Sign(rand.Reader, h[:], crypto.SHA256)

	ociSig, _ := static.NewSignature(p,
		base64.StdEncoding.EncodeToString(signature),
		static.WithCertChain(certs.LeafCertPEM, appendSlices([][]byte{certs.SubCertPEM, certs.RootCertPEM})))

	captureOutput := func(f func()) string {
		reader, writer, err := os.Pipe()
		if err != nil {
			panic(err)
		}
		stdout := os.Stdout
		stderr := os.Stderr
		defer func() {
			os.Stdout = stdout
			os.Stderr = stderr
			log.SetOutput(os.Stderr)
		}()
		os.Stdout = writer
		os.Stderr = writer
		log.SetOutput(writer)
		out := make(chan string)
		wg := new(sync.WaitGroup)
		wg.Add(1)
		go func() {
			var buf bytes.Buffer
			wg.Done()
			io.Copy(&buf, reader)
			out <- buf.String()
		}()
		wg.Wait()
		f()
		writer.Close()
		return <-out
	}
	_ = captureOutput

	out := captureOutput(func() {
		ui.RunWithTestCtx(func(ctx context.Context, _ ui.WriteFunc) {
			PrintVerification(ctx, []oci.Signature{ociSig}, "json")
		})
	})
	prettyPrint := func(b []byte) ([]byte, error) {
		var out bytes.Buffer
		err := json.Indent(&out, b, "", "    ")
		return out.Bytes(), err
	}
	i, err := prettyPrint([]byte(out))
	if err != nil {
		t.Fatal(err.Error())
	}
	assert.JSONEq(t, wantPayload, string(i))
}

func appendSlices(slices [][]byte) []byte {
	totalLen := 0
	for _, s := range slices {
		totalLen += len(s)
	}
	tmp := make([]byte, 0, totalLen)
	for _, s := range slices {
		tmp = append(tmp, s...)
	}
	return tmp
}

func TestVerifyCertMissingSubject(t *testing.T) {
	ctx := context.Background()
	verifyCommand := VerifyCommand{
		CertRef: "cert.pem",
		CertVerifyOptions: options.CertVerifyOptions{
			CertOidcIssuer: "issuer",
		},
	}

	err := verifyCommand.Exec(ctx, []string{"foo", "bar", "baz"})
	if err == nil {
		t.Fatal("verify expected 'need --certificate-identity'")
	}
}

func TestVerifyCertMissingIssuer(t *testing.T) {
	ctx := context.Background()
	verifyCommand := VerifyCommand{
		CertRef: "cert.pem",
		CertVerifyOptions: options.CertVerifyOptions{
			CertIdentity: "identity",
		},
	}

	err := verifyCommand.Exec(ctx, []string{"foo", "bar", "baz"})
	if err == nil {
		t.Fatal("verify expected 'need --certificate-oidc-issuer'")
	}
}

func TestVerifyMutuallyExclusiveFlags(t *testing.T) {
	ctx := context.Background()
	tts := []struct {
		name          string
		cmd           VerifyCommand
		expectedError error
	}{
		{
			name: "both key and cert identity",
			cmd: VerifyCommand{
				KeyRef: "key.pub",
				CertVerifyOptions: options.CertVerifyOptions{
					CertIdentity: "hello@foo.com",
				},
			},
			expectedError: &options.KeyAndIdentityParseError{},
		},
		{
			name: "both key and cert identity regexp",
			cmd: VerifyCommand{
				KeyRef: "key.pub",
				CertVerifyOptions: options.CertVerifyOptions{
					CertIdentityRegexp: "^.*@foo.com$",
				},
			},
			expectedError: &options.KeyAndIdentityParseError{},
		},
		{
			name: "both cert identity and cert identity regexp",
			cmd: VerifyCommand{
				CertVerifyOptions: options.CertVerifyOptions{
					CertIdentity:       "hello@foo.com",
					CertIdentityRegexp: "^.*@foo.com$",
				},
			},
			expectedError: &options.KeyAndIdentityParseError{},
		},
		{
			name: "both key and security key",
			cmd: VerifyCommand{
				KeyRef: "key.pub",
				Sk:     true,
			},
			expectedError: &options.PubKeyParseError{},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Exec(ctx, []string{"foo", "bar", "baz"})
			if !errors.Is(err, tt.expectedError) {
				t.Fatalf("expected %T, got: %T, %v", tt.expectedError, err, err)
			}
		})
	}
}

func TestLoadCertsKeylessVerification(t *testing.T) {
	certs := getTestCerts(t)
	certChainFile := makeCertChainFile(t, certs.RootCertPEM, certs.SubCertPEM, certs.LeafCertPEM)
	rootsFile, intermediatesFile := makeRootsIntermediatesFiles(t, certs.RootCertPEM, certs.SubCertPEM)
	tests := []struct {
		name             string
		certChain        string
		caRoots          string
		caIntermediates  string
		co               *cosign.CheckOpts
		sigstoreRootFile string
		wantErr          bool
	}{
		{
			name:    "default fulcio",
			wantErr: false,
		},
		{
			name:             "non-existent SIGSTORE_ROOT_FILE",
			sigstoreRootFile: "tesdata/nosuch-asdfjkl.pem",
			wantErr:          true,
		},
		{
			name:      "good certchain",
			certChain: certChainFile,
			wantErr:   false,
		},
		{
			name:      "bad certchain",
			certChain: "testdata/nosuch-certchain-file.pem",
			wantErr:   true,
		},
		{
			name:    "roots",
			caRoots: rootsFile,
			wantErr: false,
		},
		{
			name:    "bad roots",
			caRoots: "testdata/nosuch-roots-file.pem",
			wantErr: true,
		},
		{
			name:            "roots and intermediate",
			caRoots:         rootsFile,
			caIntermediates: intermediatesFile,
			wantErr:         false,
		},
		{
			name:            "bad roots good intermediate",
			caRoots:         "testdata/nosuch-roots-file.pem",
			caIntermediates: intermediatesFile,
			wantErr:         true,
		},
		{
			name:            "good roots bad intermediate",
			caRoots:         rootsFile,
			caIntermediates: "testdata/nosuch-intermediates-file.pem",
			wantErr:         true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.sigstoreRootFile != "" {
				os.Setenv("SIGSTORE_ROOT_FILE", tt.sigstoreRootFile)
			} else {
				t.Setenv("SIGSTORE_ROOT_FILE", "")
			}
			fulcioroots.ReInit()
			if tt.co == nil {
				tt.co = &cosign.CheckOpts{}
			}

			err := loadCertsKeylessVerification(tt.certChain, tt.caRoots, tt.caIntermediates, tt.co)
			if err == nil && tt.wantErr {
				t.Fatalf("expected error but got none")
			} else if err != nil && !tt.wantErr {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
func TestTransformOutputSuccess(t *testing.T) {
	// Build minimal in-toto statement
	stmt := `{
	  "_type": "https://in-toto.io/Statement/v0.1",
	  "subject": [
		{ "name": "artifact", "digest": { "sha256": "deadbeef" }, "annotations": { "foo": "bar" } }
	  ],
	  "predicateType": "https://slsa.dev/provenance/v0.2"
	}`
	// DSSE payloadType for in-toto
	payloadType := "application/vnd.in-toto+json"
	encodedStmt := base64.StdEncoding.EncodeToString([]byte(stmt))
	dsseEnv := fmt.Sprintf(`{
	  "payloadType": "%s",
	  "payload": "%s",
	  "signatures": [
		{ "keyid": "test", "sig": "MAo=" }
	  ]
	}`, payloadType, encodedStmt)

	sig, err := static.NewSignature([]byte(dsseEnv), "")
	if err != nil {
		t.Fatalf("creating static signature: %v", err)
	}
	fmt.Println(dsseEnv)

	name := "example.com/my/image"
	out, err := transformOutput([]oci.Signature{sig}, name)
	if err != nil {
		t.Fatalf("transformOutput returned error: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 transformed signature, got %d", len(out))
	}

	payloadBytes, err := out[0].Payload()
	if err != nil {
		t.Fatalf("reading transformed payload: %v", err)
	}

	var sci payload.SimpleContainerImage
	if err := json.Unmarshal(payloadBytes, &sci); err != nil {
		t.Fatalf("unmarshal transformed payload: %v", err)
	}

	assert.Equal(t, name, sci.Critical.Identity.DockerReference, "docker reference mismatch")
	assert.Equal(t, "sha256:deadbeef", sci.Critical.Image.DockerManifestDigest, "digest mismatch")
	assert.Equal(t, "https://slsa.dev/provenance/v0.2", sci.Critical.Type, "type mismatch")
	assert.Equal(t, map[string]any{"foo": "bar"}, sci.Optional, "missing annotation")
}

func TestVerifySkWithoutIdentities(t *testing.T) {
	ctx := context.Background()
	verifyCommand := VerifyCommand{
		Sk: true,
	}

	err := verifyCommand.Exec(ctx, []string{"foo"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "opening piv token") {
		t.Fatalf("expected PIV error, got: %v", err)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestSignAndVerifyWithHTTPTargetRepository(t *testing.T) {
	r := registry.New(registry.WithReferrersSupport(true))
	s := httptest.NewServer(r)
	defer s.Close()

	u, err := url.Parse(s.URL)
	assert.NoError(t, err)
	host := u.Host

	// Route registry.local:5000 over HTTP to the in-memory registry.
	rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		reqClone := req.Clone(req.Context())
		reqClone.URL.Host = host
		reqClone.Host = host
		return http.DefaultTransport.RoundTrip(reqClone)
	})

	td := t.TempDir()
	keys, err := cosign.GenerateKeyPair(func(bool) ([]byte, error) { return nil, nil })
	assert.NoError(t, err)
	privKeyPath := filepath.Join(td, "cosign.key")
	pubKeyPath := filepath.Join(td, "cosign.pub")
	assert.NoError(t, os.WriteFile(privKeyPath, keys.PrivateBytes, 0o600))
	assert.NoError(t, os.WriteFile(pubKeyPath, keys.PublicBytes, 0o600))

	ro := &options.RootOptions{Timeout: options.DefaultTimeout}
	ko := options.KeyOpts{
		KeyRef:           privKeyPath,
		PassFunc:         func(bool) ([]byte, error) { return nil, nil },
		SkipConfirmation: true,
	}
	regOpts := options.RegistryOptions{
		AllowHTTPRegistry:  true,
		RegistryClientOpts: []remote.Option{remote.WithTransport(rt)},
	}

	for _, tc := range []struct {
		name              string
		newBundleFormat   bool
		experimentalOCI11 bool
	}{
		{name: "legacy", newBundleFormat: false},
		{name: "new-bundle-format", newBundleFormat: true},
		{name: "oci-1-1-referrers", newBundleFormat: false, experimentalOCI11: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			targetRepoStr := fmt.Sprintf("registry.local:5000/target/%s", tc.name)
			t.Setenv("COSIGN_REPOSITORY", targetRepoStr)

			// Write the image both to the loopback host (which does not need name.Insecure)
			// and to registry.local:5000 (which requires name.Insecure / AllowHTTPRegistry).
			loopbackImgRefStr := fmt.Sprintf("%s/source/%s:latest", host, tc.name)
			loopbackImgRef, err := name.ParseReference(loopbackImgRefStr)
			assert.NoError(t, err)
			assert.NoError(t, remote.Write(loopbackImgRef, empty.Image, remote.WithTransport(rt)))

			imgRefStr := fmt.Sprintf("registry.local:5000/source/%s:latest", tc.name)
			imgRef, err := name.ParseReference(imgRefStr, name.Insecure)
			assert.NoError(t, err)
			assert.NoError(t, remote.Write(imgRef, empty.Image, remote.WithTransport(rt)))

			koCase := ko
			koCase.NewBundleFormat = tc.newBundleFormat

			so := options.SignOptions{
				Upload:          true,
				TlogUpload:      false,
				NewBundleFormat: tc.newBundleFormat,
				Registry:        regOpts,
			}
			if tc.experimentalOCI11 {
				so.RegistryExperimental.RegistryReferrersMode = options.RegistryReferrersModeOCI11
			}

			// Without AllowHTTPRegistry, signing even a loopback source image must fail
			// specifically when pushing to the HTTP COSIGN_REPOSITORY (registry.local:5000).
			soNoHTTP := so
			soNoHTTP.Registry.AllowHTTPRegistry = false
			assert.Error(t, sign.SignCmd(t.Context(), ro, koCase, soNoHTTP, []string{loopbackImgRefStr}))

			// With AllowHTTPRegistry, signing from HTTP source to HTTP COSIGN_REPOSITORY succeeds.
			assert.NoError(t, sign.SignCmd(t.Context(), ro, koCase, so, []string{imgRefStr}))

			verifyCmd := VerifyCommand{
				KeyRef:            pubKeyPath,
				CheckClaims:       true,
				IgnoreTlog:        true,
				HashAlgorithm:     crypto.SHA256,
				RegistryOptions:   regOpts,
				ExperimentalOCI11: tc.experimentalOCI11,
				CommonVerifyOptions: options.CommonVerifyOptions{
					NewBundleFormat:   tc.newBundleFormat,
					ExperimentalOCI11: tc.experimentalOCI11,
				},
			}

			// Without COSIGN_REPOSITORY set, verification must fail because the signature/bundle
			// was written to the target repository, not the source repository.
			t.Setenv("COSIGN_REPOSITORY", "")
			assert.Error(t, verifyCmd.Exec(t.Context(), []string{imgRefStr}))
			t.Setenv("COSIGN_REPOSITORY", targetRepoStr)

			// Without AllowHTTPRegistry, verification against the loopback source image must fail
			// specifically when reading from the HTTP COSIGN_REPOSITORY.
			verifyNoHTTP := verifyCmd
			verifyNoHTTP.AllowHTTPRegistry = false
			assert.Error(t, verifyNoHTTP.Exec(t.Context(), []string{loopbackImgRefStr}))

			// With AllowHTTPRegistry, verification from COSIGN_REPOSITORY succeeds.
			assert.NoError(t, verifyCmd.Exec(t.Context(), []string{imgRefStr}))
		})
	}
}
