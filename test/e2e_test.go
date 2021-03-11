package test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/sigstore/cosign/pkg/cosign"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"

	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/cmd/cosign/cli"
)

var keyPass = []byte("hello")

var passFunc = func(_ bool) ([]byte, error) {
	return keyPass, nil
}

var verify = func(k, i string, b bool, a map[string]string) error {
	pk, err := cosign.LoadPublicKey(k)
	if err != nil {
		return err
	}
	co := cosign.CheckOpts{
		PubKey:      pk,
		Annotations: a,
		Claims:      b,
		Tlog:        os.Getenv("TLOG") == "1",
	}
	_, err = cli.VerifyCmd(context.Background(), i, co)
	return err
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

	// Now sign the image
	must(cli.SignCmd(ctx, privKeyPath, imgName, true, "", nil, "", passFunc, false), t)

	// Now verify should work!
	must(verify(pubKeyPath, imgName, true, nil), t)

	// Look for a specific annotation
	mustErr(verify(pubKeyPath, imgName, true, map[string]string{"foo": "bar"}), t)

	// Sign the image with an annotation
	must(cli.SignCmd(ctx, privKeyPath, imgName, true, "", map[string]string{"foo": "bar"}, "", passFunc, false), t)

	// It should match this time.
	must(verify(pubKeyPath, imgName, true, map[string]string{"foo": "bar"}), t)

	// But two doesn't work
	mustErr(verify(pubKeyPath, imgName, true, map[string]string{"foo": "bar", "baz": "bat"}), t)
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
	must(cli.SignCmd(ctx, priv1, imgName, true, "", nil, "", passFunc, false), t)
	// Now verify should work with that one, but not the other
	must(verify(pub1, imgName, true, nil), t)
	mustErr(verify(pub2, imgName, true, nil), t)

	// Now sign with the other key too
	must(cli.SignCmd(ctx, priv2, imgName, true, "", nil, "", passFunc, false), t)

	// Now verify should work with both
	must(verify(pub1, imgName, true, nil), t)
	must(verify(pub2, imgName, true, nil), t)
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
	ss := cosign.SimpleSigning{}
	must(json.Unmarshal(b.Bytes(), &ss), t)

	equals(desc.Digest.String(), ss.Critical.Image.DockerManifestDigest, t)

	// Now try with some annotations.
	b.Reset()
	a := map[string]string{"foo": "bar"}
	must(cli.GenerateCmd(context.Background(), imgName, a, &b), t)
	must(json.Unmarshal(b.Bytes(), &ss), t)

	equals(desc.Digest.String(), ss.Critical.Image.DockerManifestDigest, t)
	equals(ss.Optional["foo"], "bar", t)
}

func keypair(t *testing.T, td string) (*cosign.Keys, string, string) {
	if err := os.Chdir(td); err != nil {
		t.Fatal(err)
	}
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
		signatureType cli.SignatureArgType
		expectedErr   bool
	}{
		"file containing signature": {
			signature:     "testsignaturefile",
			signatureType: cli.FileSignature,
			expectedErr:   false,
		},
		"raw signature as argument": {
			signature:     "testsignatureraw",
			signatureType: cli.RawSignature,
			expectedErr:   false,
		},
		"empty signature as argument": {
			signature:     "",
			signatureType: cli.RawSignature,
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
			if testCase.signatureType == cli.FileSignature {
				sigRef = mkfile(signature, td, t)
			} else {
				sigRef = signature
			}

			// Upload it!
			err := cli.UploadCmd(ctx, sigRef, payloadPath, imgName)
			if testCase.expectedErr {
				mustErr(err, t)
			} else {
				must(err, t)
			}

			// Now download it!
			signatures, _, err := cosign.FetchSignatures(ref)
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

func setenv(t *testing.T, k, v string) func() {
	if err := os.Setenv(k, v); err != nil {
		t.Fatalf("error setitng env: %v", err)
	}
	return func() {
		os.Unsetenv(cosign.ServerEnv)
	}
}

func TestTlog(t *testing.T) {
	defer setenv(t, cosign.ServerEnv, "http://127.0.0.1:3000")()

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
	must(cli.SignCmd(ctx, privKeyPath, imgName, true, "", nil, "", passFunc, false), t)

	// Now verify should work!
	must(verify(pubKeyPath, imgName, true, nil), t)

	// Now we turn on the tlog!
	defer setenv(t, cosign.TLogEnv, "1")()

	// Verify shouldn't work since we haven't put anything in it yet.
	mustErr(verify(pubKeyPath, imgName, true, nil), t)

	// Sign again with the tlog env var on
	must(cli.SignCmd(ctx, privKeyPath, imgName, true, "", nil, "", passFunc, false), t)
	// And now verify works!
	must(verify(pubKeyPath, imgName, true, nil), t)
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
		munged := cosign.Munge(remoteImage.Descriptor)
		ref, _ := name.ParseReference(munged)
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
