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

// +build e2e

package test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/sigstore/cosign/cmd/cosign/cli"
	"github.com/sigstore/cosign/cmd/cosign/cli/attach"
	"github.com/sigstore/cosign/cmd/cosign/cli/download"
	"github.com/sigstore/cosign/cmd/cosign/cli/upload"
	sget "github.com/sigstore/cosign/cmd/sget/cli"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/kubernetes"
	cremote "github.com/sigstore/cosign/pkg/cosign/remote"
	"github.com/sigstore/sigstore/pkg/signature/payload"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	serverEnv       = "REKOR_SERVER"
)

var keyPass = []byte("hello")

var passFunc = func(_ bool) ([]byte, error) {
	return keyPass, nil
}

var verify = func(keyRef, imageRef string, checkClaims bool, annotations map[string]interface{}) error {
	cmd := cli.VerifyCommand{
		KeyRef:      keyRef,
		CheckClaims: checkClaims,
		Annotations: &annotations,
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
	mustErr(verify(pubKeyPath, imgName, true, nil), t)
	// So should download
	mustErr(download.SignatureCmd(ctx, imgName), t)

	// Now sign the image
	ko := cli.KeyOpts{KeyRef: privKeyPath, PassFunc: passFunc}
	must(cli.SignCmd(ctx, ko, nil, imgName, "", true, "", false, false), t)

	// Now verify and download should work!
	must(verify(pubKeyPath, imgName, true, nil), t)
	must(download.SignatureCmd(ctx, imgName), t)

	// Look for a specific annotation
	mustErr(verify(pubKeyPath, imgName, true, map[string]interface{}{"foo": "bar"}), t)

	// Sign the image with an annotation
	annotations := map[string]interface{}{"foo": "bar"}
	must(cli.SignCmd(ctx, ko, annotations, imgName, "", true, "", false, false), t)

	// It should match this time.
	must(verify(pubKeyPath, imgName, true, map[string]interface{}{"foo": "bar"}), t)

	// But two doesn't work
	mustErr(verify(pubKeyPath, imgName, true, map[string]interface{}{"foo": "bar", "baz": "bat"}), t)
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
	ko := cli.KeyOpts{KeyRef: privKeyPath, PassFunc: passFunc}
	must(cli.SignCmd(ctx, ko, nil, imgName, "", true, "", false, false), t)

	// Now verify and download should work!
	must(verify(pubKeyPath, imgName, true, nil), t)
	must(download.SignatureCmd(ctx, imgName), t)

	// Now clean signature from the given image
	must(cli.CleanCmd(ctx, imgName), t)

	// It doesn't work
	mustErr(verify(pubKeyPath, imgName, true, nil), t)
}

func TestBundle(t *testing.T) {
	// use rekor prod since we have hardcoded the public key
	defer setenv(t, serverEnv, "https://rekor.sigstore.dev")()
	// turn on the tlog
	defer setenv(t, cli.ExperimentalEnv, "1")()

	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "cosign-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, pubKeyPath := keypair(t, td)

	ctx := context.Background()

	ko := cli.KeyOpts{
		KeyRef:   privKeyPath,
		PassFunc: passFunc,
	}

	// Sign the image
	must(cli.SignCmd(ctx, ko, nil, imgName, "", true, "", false, false), t)
	// Make sure verify works
	must(verify(pubKeyPath, imgName, true, nil), t)

	// Make sure offline verification works with bundling
	// use rekor prod since we have hardcoded the public key
	os.Setenv(serverEnv, "notreal")
	must(verify(pubKeyPath, imgName, true, nil), t)
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
	mustErr(verify(pubKeyPath, imgName, true, nil), t)
	// So should download
	mustErr(download.SignatureCmd(ctx, imgName), t)

	// Now sign the image
	ko := cli.KeyOpts{KeyRef: privKeyPath, PassFunc: passFunc}
	must(cli.SignCmd(ctx, ko, nil, imgName, "", true, "", false, false), t)

	// Now verify and download should work!
	must(verify(pubKeyPath, imgName, true, nil), t)
	must(download.SignatureCmd(ctx, imgName), t)

	// Signing again should work just fine...
	must(cli.SignCmd(ctx, ko, nil, imgName, "", true, "", false, false), t)
	// but a duplicate signature should not be a uploaded
	sigRepo, err := cli.TargetRepositoryForImage(ref)
	if err != nil {
		t.Fatalf("failed to get signature repository: %v", err)
	}

	signatures, err := cosign.FetchSignaturesForImage(ctx, ref, sigRepo, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		t.Fatalf("failed to fetch signatures: %v", err)
	}
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

	must(verify(keyRef, img, true, nil), t)
}

func TestGenerateKeyPairEnvVar(t *testing.T) {
	defer setenv(t, "COSIGN_PASSWORD", "foo")()
	keys, err := cosign.GenerateKeyPair(cli.GetPass)
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
	if err := kubernetes.KeyPairSecret(ctx, fmt.Sprintf("k8s://%s/%s", namespace, name), cli.GetPass); err != nil {
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
	mustErr(verify(pub1, imgName, true, nil), t)
	mustErr(verify(pub2, imgName, true, nil), t)

	// Now sign the image with one key
	ko := cli.KeyOpts{KeyRef: priv1, PassFunc: passFunc}
	must(cli.SignCmd(ctx, ko, nil, imgName, "", true, "", false, false), t)
	// Now verify should work with that one, but not the other
	must(verify(pub1, imgName, true, nil), t)
	mustErr(verify(pub2, imgName, true, nil), t)

	// Now sign with the other key too
	ko.KeyRef = priv2
	must(cli.SignCmd(ctx, ko, nil, imgName, "", true, "", false, false), t)

	// Now verify should work with both
	must(verify(pub1, imgName, true, nil), t)
	must(verify(pub2, imgName, true, nil), t)
}

func TestSignBlob(t *testing.T) {

	var blob = "someblob"
	td1 := t.TempDir()
	td2 := t.TempDir()
	t.Cleanup(func() {
		os.RemoveAll(td1)
		os.RemoveAll(td2)
	})
	bp := filepath.Join(td1, blob)

	if err := ioutil.WriteFile(bp, []byte(blob), 0644); err != nil {
		t.Fatal(err)
	}

	_, privKeyPath1, pubKeyPath1 := keypair(t, td1)
	_, _, pubKeyPath2 := keypair(t, td2)

	ctx := context.Background()

	ko1 := cli.KeyOpts{
		KeyRef: pubKeyPath1,
	}
	ko2 := cli.KeyOpts{
		KeyRef: pubKeyPath2,
	}
	// Verify should fail on a bad input
	mustErr(cli.VerifyBlobCmd(ctx, ko1, "", "badsig", blob), t)
	mustErr(cli.VerifyBlobCmd(ctx, ko2, "", "badsig", blob), t)

	// Now sign the blob with one key
	ko := cli.KeyOpts{
		KeyRef:   privKeyPath1,
		PassFunc: passFunc,
	}
	sig, err := cli.SignBlobCmd(ctx, ko, bp, true, "")
	if err != nil {
		t.Fatal(err)
	}
	// Now verify should work with that one, but not the other
	must(cli.VerifyBlobCmd(ctx, ko1, "", string(sig), bp), t)
	mustErr(cli.VerifyBlobCmd(ctx, ko2, "", string(sig), bp), t)
}

func TestGenerate(t *testing.T) {
	repo, stop := reg(t)
	defer stop()

	imgName := path.Join(repo, "cosign-e2e")
	_, desc, cleanup := mkimage(t, imgName)
	defer cleanup()

	// Generate the payload for the image, and check the digest.
	b := bytes.Buffer{}
	must(cli.GenerateCmd(context.Background(), imgName, nil, &b), t)
	ss := payload.SimpleContainerImage{}
	must(json.Unmarshal(b.Bytes(), &ss), t)

	equals(desc.Digest.String(), ss.Critical.Image.DockerManifestDigest, t)

	// Now try with some annotations.
	b.Reset()
	a := map[string]interface{}{"foo": "bar"}
	must(cli.GenerateCmd(context.Background(), imgName, a, &b), t)
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
	if err := ioutil.WriteFile(privKeyPath, keys.PrivateBytes, 0600); err != nil {
		t.Fatal(err)
	}

	pubKeyPath := filepath.Join(td, "cosign.pub")
	if err := ioutil.WriteFile(pubKeyPath, keys.PublicBytes, 0600); err != nil {
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
			err := attach.SignatureCmd(ctx, sigRef, payloadPath, imgName)
			if testCase.expectedErr {
				mustErr(err, t)
			} else {
				must(err, t)
			}

			// Now download it!
			sigRepo, err := cli.TargetRepositoryForImage(ref)
			if err != nil {
				t.Fatalf("failed to get signature repository: %v", err)
			}
			signatures, err := cosign.FetchSignaturesForImage(ctx, ref, sigRepo, remote.WithAuthFromKeychain(authn.DefaultKeychain))
			if testCase.expectedErr {
				mustErr(err, t)
			} else {
				must(err, t)

				if len(signatures) != 1 {
					t.Error("unexpected signatures")
				}
				if diff := cmp.Diff(signatures[0].Base64Signature, signature); diff != "" {
					t.Error(diff)
				}
				if diff := cmp.Diff(signatures[0].Payload, []byte(payload)); diff != "" {
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
	files := []cremote.File{{
		Path: payloadPath,
	}}
	must(upload.BlobCmd(ctx, files, "", imgName), t)

	// Check it
	ref, err := name.ParseReference(imgName)
	if err != nil {
		t.Fatal(err)
	}

	// Now download it with sget (this should fail by tag)
	if _, err := sget.SgetCmd(ctx, imgName, ""); err == nil {
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

	// But pass by digest
	rc, err := sget.SgetCmd(ctx, imgName+"@"+dgst.String(), "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ioutil.ReadAll(rc)
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
	_, err := download.SBOMCmd(ctx, img.Name(), &out)
	if err == nil {
		t.Fatal("Expected error")
	}
	t.Log(out)
	out.Reset()

	// Upload it!
	must(attach.SBOMCmd(ctx, "./testdata/bom-go-mod.spdx", "spdx", imgName), t)

	sboms, err := download.SBOMCmd(ctx, imgName, &out)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(out)
	if len(sboms) != 1 {
		t.Fatalf("Expected one sbom, got %d", len(sboms))
	}
	want, err := ioutil.ReadFile("./testdata/bom-go-mod.spdx")
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(string(want), sboms[0]); diff != "" {
		t.Errorf("diff: %s", diff)
	}
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
	defer setenv(t, serverEnv, "http://127.0.0.1:3000")()

	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "cosign-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, pubKeyPath := keypair(t, td)

	ctx := context.Background()
	// Verify should fail at first
	mustErr(verify(pubKeyPath, imgName, true, nil), t)

	// Now sign the image without the tlog
	ko := cli.KeyOpts{
		KeyRef:   privKeyPath,
		PassFunc: passFunc,
	}
	must(cli.SignCmd(ctx, ko, nil, imgName, "", true, "", false, false), t)

	// Now verify should work!
	must(verify(pubKeyPath, imgName, true, nil), t)

	// Now we turn on the tlog!
	defer setenv(t, cli.ExperimentalEnv, "1")()

	// Verify shouldn't work since we haven't put anything in it yet.
	mustErr(verify(pubKeyPath, imgName, true, nil), t)

	// Sign again with the tlog env var on
	must(cli.SignCmd(ctx, ko, nil, imgName, "", true, "", false, false), t)
	// And now verify works!
	must(verify(pubKeyPath, imgName, true, nil), t)
}

func TestGetPublicKeyCustomOut(t *testing.T) {
	td := t.TempDir()
	keys, privKeyPath, _ := keypair(t, td)
	ctx := context.Background()

	outFile := "output.pub"
	outPath := filepath.Join(td, outFile)
	outWriter, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE, 0600)
	must(err, t)

	pk := cli.Pkopts{
		KeyRef: privKeyPath,
	}
	must(cli.GetPublicKey(ctx, pk, cli.NamedWriter{Name: outPath, Writer: outWriter}, passFunc), t)

	output, err := ioutil.ReadFile(outPath)
	must(err, t)
	equals(keys.PublicBytes, output, t)
}

func mkfile(contents, td string, t *testing.T) string {
	f, err := ioutil.TempFile(td, "")
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

	if err := remote.Write(ref, img, remote.WithAuthFromKeychain(authn.DefaultKeychain)); err != nil {
		t.Fatal(err)
	}

	remoteImage, err := remote.Get(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		t.Fatal(err)
	}

	cleanup := func() {
		_ = remote.Delete(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
		ref := cosign.AttachedImageTag(ref.Context(), remoteImage, cosign.SuffixSignature)
		_ = remote.Delete(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
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
