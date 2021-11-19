//
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

//go:build e2e
// +build e2e

package test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"
	ftime "time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/sigstore/cosign/cmd/cosign/cli"
	"github.com/sigstore/cosign/cmd/cosign/cli/attach"
	"github.com/sigstore/cosign/cmd/cosign/cli/attest"
	"github.com/sigstore/cosign/cmd/cosign/cli/download"
	"github.com/sigstore/cosign/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/publickey"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/cmd/cosign/cli/upload"
	cliverify "github.com/sigstore/cosign/cmd/cosign/cli/verify"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/kubernetes"
	cremote "github.com/sigstore/cosign/pkg/cosign/remote"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	"github.com/sigstore/cosign/pkg/sget"
	sigs "github.com/sigstore/cosign/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/payload"
)

const (
	serverEnv = "REKOR_SERVER"
	rekorURL  = "https://rekor.sigstore.dev"
)

var keyPass = []byte("hello")

var passFunc = func(_ bool) ([]byte, error) {
	return keyPass, nil
}

var verify = func(keyRef, imageRef string, checkClaims bool, annotations map[string]interface{}, attachment string) error {
	cmd := cliverify.VerifyCommand{
		KeyRef:      keyRef,
		RekorURL:    rekorURL,
		CheckClaims: checkClaims,
		Annotations: sigs.AnnotationsMap{Annotations: annotations},
		Attachment:  attachment,
	}

	args := []string{imageRef}

	return cmd.Exec(context.Background(), args)
}

func TestSignVerify(t *testing.T) {
	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "cosign-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, pubKeyPath := keypair(t, td)

	ctx := context.Background()
	// Verify should fail at first
	mustErr(verify(pubKeyPath, imgName, true, nil, ""), t)
	// So should download
	mustErr(download.SignatureCmd(ctx, options.RegistryOptions{}, imgName), t)

	// Now sign the image
	ko := sign.KeyOpts{KeyRef: privKeyPath, PassFunc: passFunc}
	must(sign.SignCmd(ctx, ko, options.RegistryOptions{}, nil, []string{imgName}, "", true, "", "", false, false, ""), t)

	// Now verify and download should work!
	must(verify(pubKeyPath, imgName, true, nil, ""), t)
	must(download.SignatureCmd(ctx, options.RegistryOptions{}, imgName), t)

	// Look for a specific annotation
	mustErr(verify(pubKeyPath, imgName, true, map[string]interface{}{"foo": "bar"}, ""), t)

	// Sign the image with an annotation
	annotations := map[string]interface{}{"foo": "bar"}
	must(sign.SignCmd(ctx, ko, options.RegistryOptions{}, annotations, []string{imgName}, "", true, "", "", false, false, ""), t)

	// It should match this time.
	must(verify(pubKeyPath, imgName, true, map[string]interface{}{"foo": "bar"}, ""), t)

	// But two doesn't work
	mustErr(verify(pubKeyPath, imgName, true, map[string]interface{}{"foo": "bar", "baz": "bat"}, ""), t)
}

func TestSignVerifyClean(t *testing.T) {
	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "cosign-e2e")

	_, _, _ = mkimage(t, imgName)

	_, privKeyPath, pubKeyPath := keypair(t, td)

	ctx := context.Background()

	// Now sign the image
	ko := sign.KeyOpts{KeyRef: privKeyPath, PassFunc: passFunc}
	must(sign.SignCmd(ctx, ko, options.RegistryOptions{}, nil, []string{imgName}, "", true, "", "", false, false, ""), t)

	// Now verify and download should work!
	must(verify(pubKeyPath, imgName, true, nil, ""), t)
	must(download.SignatureCmd(ctx, options.RegistryOptions{}, imgName), t)

	// Now clean signature from the given image
	must(cli.CleanCmd(ctx, options.RegistryOptions{}, imgName), t)

	// It doesn't work
	mustErr(verify(pubKeyPath, imgName, true, nil, ""), t)
}

func TestAttestVerify(t *testing.T) {
	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "cosign-attest-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, pubKeyPath := keypair(t, td)

	ctx := context.Background()

	// Verify should fail at first
	verifyAttestation := cliverify.VerifyAttestationCommand{
		KeyRef: pubKeyPath,
	}

	// Fail case when using without type and policy flag
	mustErr(verifyAttestation.Exec(ctx, []string{imgName}), t)

	slsaAttestation := `{ "builder": { "id": "2" }, "recipe": {} }`
	slsaAttestationPath := filepath.Join(td, "attestation.slsa.json")
	if err := os.WriteFile(slsaAttestationPath, []byte(slsaAttestation), 0600); err != nil {
		t.Fatal(err)
	}

	// Now attest the image
	ko := sign.KeyOpts{KeyRef: privKeyPath, PassFunc: passFunc}
	must(attest.AttestCmd(ctx, ko, options.RegistryOptions{}, imgName, "", false, slsaAttestationPath, false,
		"custom", false, ftime.Duration(30*time.Second)), t)

	// Use cue to verify attestation
	policyPath := filepath.Join(td, "policy.cue")
	verifyAttestation.PredicateType = "slsaprovenance"
	verifyAttestation.Policies = []string{policyPath}

	// Fail case
	cuePolicy := `builder: id: "1"`
	if err := os.WriteFile(policyPath, []byte(cuePolicy), 0600); err != nil {
		t.Fatal(err)
	}

	// Success case
	cuePolicy = `builder: id: "2"`
	if err := os.WriteFile(policyPath, []byte(cuePolicy), 0600); err != nil {
		t.Fatal(err)
	}
	must(verifyAttestation.Exec(ctx, []string{imgName}), t)

	// Look for a specific annotation
	mustErr(verify(pubKeyPath, imgName, true, map[string]interface{}{"foo": "bar"}, ""), t)
}

func TestBundle(t *testing.T) {
	// turn on the tlog
	defer setenv(t, options.ExperimentalEnv, "1")()

	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "cosign-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, pubKeyPath := keypair(t, td)

	ctx := context.Background()

	ko := sign.KeyOpts{
		KeyRef:   privKeyPath,
		PassFunc: passFunc,
		RekorURL: rekorURL,
	}

	// Sign the image
	must(sign.SignCmd(ctx, ko, options.RegistryOptions{}, nil, []string{imgName}, "", true, "", "", false, false, ""), t)
	// Make sure verify works
	must(verify(pubKeyPath, imgName, true, nil, ""), t)

	// Make sure offline verification works with bundling
	// use rekor prod since we have hardcoded the public key
	os.Setenv(serverEnv, "notreal")
	must(verify(pubKeyPath, imgName, true, nil, ""), t)
}

func TestDuplicateSign(t *testing.T) {
	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "cosign-e2e")

	ref, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, pubKeyPath := keypair(t, td)

	ctx := context.Background()
	// Verify should fail at first
	mustErr(verify(pubKeyPath, imgName, true, nil, ""), t)
	// So should download
	mustErr(download.SignatureCmd(ctx, options.RegistryOptions{}, imgName), t)

	// Now sign the image
	ko := sign.KeyOpts{KeyRef: privKeyPath, PassFunc: passFunc}
	must(sign.SignCmd(ctx, ko, options.RegistryOptions{}, nil, []string{imgName}, "", true, "", "", false, false, ""), t)

	// Now verify and download should work!
	must(verify(pubKeyPath, imgName, true, nil, ""), t)
	must(download.SignatureCmd(ctx, options.RegistryOptions{}, imgName), t)

	// Signing again should work just fine...
	must(sign.SignCmd(ctx, ko, options.RegistryOptions{}, nil, []string{imgName}, "", true, "", "", false, false, ""), t)

	se, err := ociremote.SignedEntity(ref, ociremote.WithRemoteOptions(registryClientOpts(ctx)...))
	must(err, t)
	sigs, err := se.Signatures()
	must(err, t)
	signatures, err := sigs.Get()
	must(err, t)

	if len(signatures) > 1 {
		t.Errorf("expected there to only be one signature, got %v", signatures)
	}
}

func TestKeyURLVerify(t *testing.T) {
	// TODO: re-enable once distroless images are being signed by the new client
	t.Skip()
	// Verify that an image can be verified via key url
	keyRef := "https://raw.githubusercontent.com/GoogleContainerTools/distroless/main/cosign.pub"
	img := "gcr.io/distroless/base:latest"

	must(verify(keyRef, img, true, nil, ""), t)
}

func TestGenerateKeyPairEnvVar(t *testing.T) {
	defer setenv(t, "COSIGN_PASSWORD", "foo")()
	keys, err := cosign.GenerateKeyPair(generate.GetPass)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cosign.LoadECDSAPrivateKey(keys.PrivateBytes, []byte("foo")); err != nil {
		t.Fatal(err)
	}
}

func TestGenerateKeyPairK8s(t *testing.T) {
	td := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(td); err != nil {
		t.Fatal(err)
	}
	defer func() {
		os.Chdir(wd)
	}()
	password := "foo"
	defer setenv(t, "COSIGN_PASSWORD", password)()
	ctx := context.Background()
	name := "cosign-secret"
	namespace := "default"
	if err := kubernetes.KeyPairSecret(ctx, fmt.Sprintf("k8s://%s/%s", namespace, name), generate.GetPass); err != nil {
		t.Fatal(err)
	}
	// make sure the secret actually exists
	client, err := kubernetes.Client()
	if err != nil {
		t.Fatal(err)
	}
	s, err := client.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := s.Data["cosign.password"]; !ok || string(v) != password {
		t.Fatalf("password is incorrect, got %v expected %v", v, "foo")
	}
}

func TestMultipleSignatures(t *testing.T) {
	repo, stop := reg(t)
	defer stop()

	td1 := t.TempDir()
	td2 := t.TempDir()

	imgName := path.Join(repo, "cosign-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, priv1, pub1 := keypair(t, td1)
	_, priv2, pub2 := keypair(t, td2)

	ctx := context.Background()

	// Verify should fail at first for both keys
	mustErr(verify(pub1, imgName, true, nil, ""), t)
	mustErr(verify(pub2, imgName, true, nil, ""), t)

	// Now sign the image with one key
	ko := sign.KeyOpts{KeyRef: priv1, PassFunc: passFunc}
	must(sign.SignCmd(ctx, ko, options.RegistryOptions{}, nil, []string{imgName}, "", true, "", "", false, false, ""), t)
	// Now verify should work with that one, but not the other
	must(verify(pub1, imgName, true, nil, ""), t)
	mustErr(verify(pub2, imgName, true, nil, ""), t)

	// Now sign with the other key too
	ko.KeyRef = priv2
	must(sign.SignCmd(ctx, ko, options.RegistryOptions{}, nil, []string{imgName}, "", true, "", "", false, false, ""), t)

	// Now verify should work with both
	must(verify(pub1, imgName, true, nil, ""), t)
	must(verify(pub2, imgName, true, nil, ""), t)
}

func TestSignBlob(t *testing.T) {
	blob := "someblob"
	td1 := t.TempDir()
	td2 := t.TempDir()
	t.Cleanup(func() {
		os.RemoveAll(td1)
		os.RemoveAll(td2)
	})
	bp := filepath.Join(td1, blob)

	if err := os.WriteFile(bp, []byte(blob), 0644); err != nil {
		t.Fatal(err)
	}

	_, privKeyPath1, pubKeyPath1 := keypair(t, td1)
	_, _, pubKeyPath2 := keypair(t, td2)

	ctx := context.Background()

	ko1 := sign.KeyOpts{
		KeyRef: pubKeyPath1,
	}
	ko2 := sign.KeyOpts{
		KeyRef: pubKeyPath2,
	}
	// Verify should fail on a bad input
	mustErr(cliverify.VerifyBlobCmd(ctx, ko1, "", "badsig", blob), t)
	mustErr(cliverify.VerifyBlobCmd(ctx, ko2, "", "badsig", blob), t)

	// Now sign the blob with one key
	ko := sign.KeyOpts{
		KeyRef:   privKeyPath1,
		PassFunc: passFunc,
	}
	sig, err := sign.SignBlobCmd(ctx, ko, options.RegistryOptions{}, bp, true, "", "", time.Duration(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	// Now verify should work with that one, but not the other
	must(cliverify.VerifyBlobCmd(ctx, ko1, "", string(sig), bp), t)
	mustErr(cliverify.VerifyBlobCmd(ctx, ko2, "", string(sig), bp), t)
}

func TestGenerate(t *testing.T) {
	repo, stop := reg(t)
	defer stop()

	imgName := path.Join(repo, "cosign-e2e")
	_, desc, cleanup := mkimage(t, imgName)
	defer cleanup()

	// Generate the payload for the image, and check the digest.
	b := bytes.Buffer{}
	must(generate.GenerateCmd(context.Background(), options.RegistryOptions{}, imgName, nil, &b), t)
	ss := payload.SimpleContainerImage{}
	must(json.Unmarshal(b.Bytes(), &ss), t)

	equals(desc.Digest.String(), ss.Critical.Image.DockerManifestDigest, t)

	// Now try with some annotations.
	b.Reset()
	a := map[string]interface{}{"foo": "bar"}
	must(generate.GenerateCmd(context.Background(), options.RegistryOptions{}, imgName, a, &b), t)
	must(json.Unmarshal(b.Bytes(), &ss), t)

	equals(desc.Digest.String(), ss.Critical.Image.DockerManifestDigest, t)
	equals(ss.Optional["foo"], "bar", t)
}

func keypair(t *testing.T, td string) (*cosign.Keys, string, string) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(td); err != nil {
		t.Fatal(err)
	}
	defer func() {
		os.Chdir(wd)
	}()
	keys, err := cosign.GenerateKeyPair(passFunc)
	if err != nil {
		t.Fatal(err)
	}

	privKeyPath := filepath.Join(td, "cosign.key")
	if err := os.WriteFile(privKeyPath, keys.PrivateBytes, 0600); err != nil {
		t.Fatal(err)
	}

	pubKeyPath := filepath.Join(td, "cosign.pub")
	if err := os.WriteFile(pubKeyPath, keys.PublicBytes, 0600); err != nil {
		t.Fatal(err)
	}
	return keys, privKeyPath, pubKeyPath
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
		"file containing signature": {
			signature:     "testsignaturefile",
			signatureType: attach.FileSignature,
			expectedErr:   false,
		},
		"raw signature as argument": {
			signature:     "testsignatureraw",
			signatureType: attach.RawSignature,
			expectedErr:   false,
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

			var sigRef string
			if testCase.signatureType == attach.FileSignature {
				sigRef = mkfile(signature, td, t)
			} else {
				sigRef = signature
			}

			// Upload it!
			err := attach.SignatureCmd(ctx, options.RegistryOptions{}, sigRef, payloadPath, imgName)
			if testCase.expectedErr {
				mustErr(err, t)
			} else {
				must(err, t)
			}

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

func TestUploadBlob(t *testing.T) {
	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()
	ctx := context.Background()

	imgName := path.Join(repo, "/cosign-upload-e2e")
	payload := "testpayload"
	payloadPath := mkfile(payload, td, t)

	// Upload it!
	files := []cremote.File{cremote.FileFromFlag(payloadPath)}
	must(upload.BlobCmd(ctx, options.RegistryOptions{}, files, "", imgName), t)

	// Check it
	ref, err := name.ParseReference(imgName)
	if err != nil {
		t.Fatal(err)
	}

	// Now download it with sget (this should fail by tag)
	if err := sget.New(imgName, "", os.Stdout).Do(ctx); err == nil {
		t.Error("expected download to fail")
	}

	img, err := remote.Image(ref)
	if err != nil {
		t.Fatal(err)
	}
	dgst, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}

	result := &bytes.Buffer{}

	// But pass by digest
	if err := sget.New(imgName+"@"+dgst.String(), "", result).Do(ctx); err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(result)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != payload {
		t.Errorf("expected contents to be %s, got %s", payload, string(b))
	}
}

func TestAttachSBOM(t *testing.T) {
	repo, stop := reg(t)
	defer stop()
	ctx := context.Background()

	imgName := path.Join(repo, "sbom-image")
	img, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	out := bytes.Buffer{}
	_, err := download.SBOMCmd(ctx, options.RegistryOptions{}, img.Name(), &out)
	if err == nil {
		t.Fatal("Expected error")
	}
	t.Log(out.String())
	out.Reset()

	// Upload it!
	must(attach.SBOMCmd(ctx, options.RegistryOptions{}, "./testdata/bom-go-mod.spdx", "spdx", imgName), t)

	sboms, err := download.SBOMCmd(ctx, options.RegistryOptions{}, imgName, &out)
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

	// Generate key pairs to sign the sbom
	td1 := t.TempDir()
	td2 := t.TempDir()
	_, privKeyPath1, pubKeyPath1 := keypair(t, td1)
	_, _, pubKeyPath2 := keypair(t, td2)

	// Verify should fail on a bad input
	mustErr(verify(pubKeyPath1, imgName, true, nil, "sbom"), t)
	mustErr(verify(pubKeyPath2, imgName, true, nil, "sbom"), t)

	// Now sign the sbom with one key
	ko1 := sign.KeyOpts{KeyRef: privKeyPath1, PassFunc: passFunc}
	must(sign.SignCmd(ctx, ko1, options.RegistryOptions{}, nil, []string{imgName}, "", true, "", "", false, false, "sbom"), t)

	// Now verify should work with that one, but not the other
	must(verify(pubKeyPath1, imgName, true, nil, "sbom"), t)
	mustErr(verify(pubKeyPath2, imgName, true, nil, "sbom"), t)
}

func setenv(t *testing.T, k, v string) func() {
	if err := os.Setenv(k, v); err != nil {
		t.Fatalf("error setitng env: %v", err)
	}
	return func() {
		os.Unsetenv(k)
	}
}

func TestTlog(t *testing.T) {
	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "cosign-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, pubKeyPath := keypair(t, td)

	ctx := context.Background()
	// Verify should fail at first
	mustErr(verify(pubKeyPath, imgName, true, nil, ""), t)

	// Now sign the image without the tlog
	ko := sign.KeyOpts{
		KeyRef:   privKeyPath,
		PassFunc: passFunc,
		RekorURL: rekorURL,
	}
	must(sign.SignCmd(ctx, ko, options.RegistryOptions{}, nil, []string{imgName}, "", true, "", "", false, false, ""), t)

	// Now verify should work!
	must(verify(pubKeyPath, imgName, true, nil, ""), t)

	// Now we turn on the tlog!
	defer setenv(t, options.ExperimentalEnv, "1")()

	// Verify shouldn't work since we haven't put anything in it yet.
	mustErr(verify(pubKeyPath, imgName, true, nil, ""), t)

	// Sign again with the tlog env var on
	must(sign.SignCmd(ctx, ko, options.RegistryOptions{}, nil, []string{imgName}, "", true, "", "", false, false, ""), t)
	// And now verify works!
	must(verify(pubKeyPath, imgName, true, nil, ""), t)
}

func TestGetPublicKeyCustomOut(t *testing.T) {
	td := t.TempDir()
	keys, privKeyPath, _ := keypair(t, td)
	ctx := context.Background()

	outFile := "output.pub"
	outPath := filepath.Join(td, outFile)
	outWriter, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE, 0600)
	must(err, t)

	pk := publickey.Pkopts{
		KeyRef: privKeyPath,
	}
	must(publickey.GetPublicKey(ctx, pk, publickey.NamedWriter{Name: outPath, Writer: outWriter}, passFunc), t)

	output, err := os.ReadFile(outPath)
	must(err, t)
	equals(keys.PublicBytes, output, t)
}

func mkfile(contents, td string, t *testing.T) string {
	f, err := os.CreateTemp(td, "")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write([]byte(contents)); err != nil {
		t.Fatal(err)
	}
	return f.Name()
}

func mkimage(t *testing.T, n string) (name.Reference, *remote.Descriptor, func()) {
	ref, err := name.ParseReference(n, name.WeakValidation)
	if err != nil {
		t.Fatal(err)
	}
	img, err := random.Image(512, 5)
	if err != nil {
		t.Fatal(err)
	}

	regClientOpts := registryClientOpts(context.Background())

	if err := remote.Write(ref, img, regClientOpts...); err != nil {
		t.Fatal(err)
	}

	remoteImage, err := remote.Get(ref, regClientOpts...)
	if err != nil {
		t.Fatal(err)
	}

	cleanup := func() {
		_ = remote.Delete(ref, regClientOpts...)
		ref, _ := ociremote.SignatureTag(ref.Context().Digest(remoteImage.Descriptor.Digest.String()), ociremote.WithRemoteOptions(regClientOpts...))
		_ = remote.Delete(ref, regClientOpts...)
	}
	return ref, remoteImage, cleanup
}

func must(err error, t *testing.T) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func mustErr(err error, t *testing.T) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error")
	}
}

func equals(v1, v2 interface{}, t *testing.T) {
	if diff := cmp.Diff(v1, v2); diff != "" {
		t.Error(diff)
	}
}

func reg(t *testing.T) (string, func()) {
	repo := os.Getenv("COSIGN_TEST_REPO")
	if repo != "" {
		return repo, func() {}
	}

	t.Log("COSIGN_TEST_REPO unset, using fake registry")
	r := httptest.NewServer(registry.New())
	u, err := url.Parse(r.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host, r.Close
}

func registryClientOpts(ctx context.Context) []remote.Option {
	return []remote.Option{
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithContext(ctx),
	}
}
