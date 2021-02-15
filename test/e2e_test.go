// +build e2e

package test

import (
	"context"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"

	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/projectcosign/cosign/cmd/cli"
	"github.com/projectcosign/cosign/pkg/cosign"
)

var keyPass = []byte("hello")

var passFunc = func(_ bool) ([]byte, error) {
	return keyPass, nil
}

func TestSignVerify(t *testing.T) {
	repo := os.Getenv("COSIGN_TEST_REPO")
	if repo == "" {
		t.Fatal("Must set COSIGN_TEST_REPO to run e2e tests.")
	}
	td := t.TempDir()
	os.Chdir(td)

	imgName := path.Join(repo, "cosign-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, pubKeyPath := keypair(t, td)

	ctx := context.Background()
	// Verify should fail at first
	mustErr(cli.VerifyCmd(ctx, pubKeyPath, imgName, true), t)

	// Now sign the image
	must(cli.SignCmd(ctx, privKeyPath, imgName, true, "", nil, passFunc), t)

	// Now verify should work!
	must(cli.VerifyCmd(ctx, pubKeyPath, imgName, true), t)
}

func TestMultipleSignatures(t *testing.T) {
	repo := os.Getenv("COSIGN_TEST_REPO")
	if repo == "" {
		t.Fatal("Must set COSIGN_TEST_REPO to run e2e tests.")
	}
	td1 := t.TempDir()
	td2 := t.TempDir()

	imgName := path.Join(repo, "cosign-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, priv1, pub1 := keypair(t, td1)
	_, priv2, pub2 := keypair(t, td2)

	ctx := context.Background()
	// Verify should fail at first for both keys
	mustErr(cli.VerifyCmd(ctx, pub1, imgName, true), t)
	mustErr(cli.VerifyCmd(ctx, pub2, imgName, true), t)

	// Now sign the image with one key
	must(cli.SignCmd(ctx, priv1, imgName, true, "", nil, passFunc), t)
	// Now verify should work with that one, but not the other
	must(cli.VerifyCmd(ctx, pub1, imgName, true), t)
	mustErr(cli.VerifyCmd(ctx, pub2, imgName, true), t)

	// Now sign with the other key too
	must(cli.SignCmd(ctx, priv2, imgName, true, "", nil, passFunc), t)

	// Now verify should work with both
	must(cli.VerifyCmd(ctx, pub1, imgName, true), t)
	must(cli.VerifyCmd(ctx, pub2, imgName, true), t)
}

func keypair(t *testing.T, td string) (*cosign.Keys, string, string) {
	os.Chdir(td)
	keys, err := cosign.GenerateKeyPair(passFunc)
	if err != nil {
		t.Fatal(err)
	}

	privKeyPath := filepath.Join(td, "cosign.key")
	ioutil.WriteFile(privKeyPath, keys.PrivateBytes, 0600)

	pubKeyPath := filepath.Join(td, "cosign.pub")
	ioutil.WriteFile(pubKeyPath, keys.PublicBytes, 0600)
	return keys, privKeyPath, pubKeyPath
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
		remote.Delete(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
		munged := cosign.Munge(remoteImage.Descriptor)
		ref, _ := name.ParseReference(munged)
		remote.Delete(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	}
	return ref, remoteImage, cleanup
}

func must(err error, t *testing.T) {
	if err != nil {
		t.Fatal(err)
	}
}

func mustErr(err error, t *testing.T) {
	if err == nil {
		t.Fatal("expected error")
	}
}
