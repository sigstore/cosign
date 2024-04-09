//
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

//go:build e2e

package test

import (
	"context"
	"crypto"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	// Initialize all known client auth plugins
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	cliverify "github.com/sigstore/cosign/v2/cmd/cosign/cli/verify"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	sigs "github.com/sigstore/cosign/v2/pkg/signature"
)

const (
	rekorURL  = "http://127.0.0.1:3000"
	fulcioURL = "http://127.0.0.1:5555"
	certID    = "foo@bar.com"
)

var keyPass = []byte("hello")

var passFunc = func(_ bool) ([]byte, error) {
	return keyPass, nil
}

var verify = func(keyRef, imageRef string, checkClaims bool, annotations map[string]interface{}, attachment string, skipTlogVerify bool) error {
	cmd := cliverify.VerifyCommand{
		KeyRef:        keyRef,
		RekorURL:      rekorURL,
		CheckClaims:   checkClaims,
		Annotations:   sigs.AnnotationsMap{Annotations: annotations},
		Attachment:    attachment,
		HashAlgorithm: crypto.SHA256,
		MaxWorkers:    10,
		IgnoreTlog:    skipTlogVerify,
	}

	args := []string{imageRef}

	return cmd.Exec(context.Background(), args)
}

var verifyTSA = func(keyRef, imageRef string, checkClaims bool, annotations map[string]interface{}, attachment, tsaCertChain string, skipTlogVerify bool) error {
	cmd := cliverify.VerifyCommand{
		KeyRef:           keyRef,
		RekorURL:         rekorURL,
		CheckClaims:      checkClaims,
		Annotations:      sigs.AnnotationsMap{Annotations: annotations},
		Attachment:       attachment,
		HashAlgorithm:    crypto.SHA256,
		TSACertChainPath: tsaCertChain,
		IgnoreTlog:       skipTlogVerify,
		MaxWorkers:       10,
	}

	args := []string{imageRef}

	return cmd.Exec(context.Background(), args)
}

var verifyKeylessTSA = func(imageRef string, tsaCertChain string, skipSCT bool, skipTlogVerify bool) error {
	cmd := cliverify.VerifyCommand{
		CertVerifyOptions: options.CertVerifyOptions{
			CertOidcIssuerRegexp: ".*",
			CertIdentityRegexp:   ".*",
		},
		RekorURL:         rekorURL,
		HashAlgorithm:    crypto.SHA256,
		TSACertChainPath: tsaCertChain,
		IgnoreSCT:        skipSCT,
		IgnoreTlog:       skipTlogVerify,
		MaxWorkers:       10,
	}

	args := []string{imageRef}

	return cmd.Exec(context.Background(), args)
}

// Used to verify local images stored on disk
var verifyLocal = func(keyRef, path string, checkClaims bool, annotations map[string]interface{}, attachment string) error {
	cmd := cliverify.VerifyCommand{
		KeyRef:        keyRef,
		RekorURL:      rekorURL,
		CheckClaims:   checkClaims,
		Annotations:   sigs.AnnotationsMap{Annotations: annotations},
		Attachment:    attachment,
		HashAlgorithm: crypto.SHA256,
		LocalImage:    true,
		MaxWorkers:    10,
	}

	args := []string{path}

	return cmd.Exec(context.Background(), args)
}

var verifyOffline = func(keyRef, imageRef string, checkClaims bool, annotations map[string]interface{}, attachment string) error {
	cmd := cliverify.VerifyCommand{
		KeyRef:        keyRef,
		RekorURL:      "notreal",
		Offline:       true,
		CheckClaims:   checkClaims,
		Annotations:   sigs.AnnotationsMap{Annotations: annotations},
		Attachment:    attachment,
		HashAlgorithm: crypto.SHA256,
		MaxWorkers:    10,
	}

	args := []string{imageRef}

	return cmd.Exec(context.Background(), args)
}

var ro = &options.RootOptions{Timeout: options.DefaultTimeout}

func keypair(t *testing.T, td string) (*cosign.KeysBytes, string, string) {
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

func importKeyPair(t *testing.T, td string) (*cosign.KeysBytes, string, string) {

	const validrsa1 = `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAx5piWVlE62NnZ0UzJ8Z6oKiKOC4dbOZ1HsNhIRtqkM+Oq4G+
25yq6P+0JU/Qvr9veOGEb3R/J9u8JBo+hv2i5X8OtgvP2V2pi6f1s6vK7L0+6uRb
4YTT/UdMshaVf97MgEqbq41Jf/cuvh+3AV0tZ1BpixZg4aXMKpY6HUP69lbsu27o
SUN1myMv7TSgZiV4CYs3l/gkEfpysBptWlcHRuw5RsB+C0RbjRtbJ/5VxmE/vd3M
lafd5t1WSpMb8yf0a84u5NFaXwZ7CweMfXeOddS0yb19ShSuW3PPRadruBM1mq15
js9GfagPxDS75Imcs+fA62lWvHxEujTGjYHxawIDAQABAoIBAH+sgLwmHa9zJfEo
klAe5NFe/QpydN/ziXbkAnzqzH9URC3wD+TpkWj4JoK3Sw635NWtasjf+3XDV9S/
9L7j/g5N91r6sziWcJykEsWaXXKQmm4lI6BdFjwsHyLKz1W7bZOiJXDWLu1rbrqu
DqEQuLoc9WXCKrYrFy0maoXNtfla/1p05kKN0bMigcnnyAQ+xBTwoyco4tkIz5se
IYxorz7qzXrkHQI+knz5BawmNe3ekoSaXUPoLoOR7TRTGsLteL5yukvWAi8S/0rE
gftC+PZCQpoQhSUYq7wXe7RowJ1f+kXb7HsSedOTfTSW1D/pUb/uW+CcRKig42ZI
I9H9TAECgYEA5XGBML6fJyWVqx64sHbUAjQsmQ0RwU6Zo7sqHIEPf6tYVYp7KtzK
KOfi8seOOL5FSy4pjCo11Dzyrh9bn45RNmtjSYTgOnVPSoCfuRNfOcpG+/wCHjYf
EjDvdrCpbg59kVUeaMeBDiyWAlM48HJAn8O7ez2U/iKQCyJmOIwFhSkCgYEA3rSz
Fi1NzqYWxWos4NBmg8iKcQ9SMkmPdgRLAs/WNnZJ8fdgJZwihevkXGytRGJEmav2
GMKRx1g6ey8fjXTQH9WM8X/kJC5fv8wLHnUCH/K3Mcp9CYwn7PFvSnBr4kQoc/el
bURhcF1+/opEC8vNX/Wk3zAG7Xs1PREXlH2SIHMCgYBV/3kgwBH/JkM25EjtO1yz
hsLAivmAruk/SUO7c1RP0fVF+qW3pxHOyztxLALOmeJ3D1JbSubqKf377Zz17O3b
q9yHDdrNjnKtxhAX2n7ytjJs+EQC9t4mf1kB761RpvTBqFnBhCWHHocLUA4jcW9v
cnmu86IIrwO2aKpPv4vCIQKBgHU9gY3qOazRSOmSlJ+hdmZn+2G7pBTvHsQNTIPl
cCrpqNHl3crO4GnKHkT9vVVjuiOAIKU2QNJFwzu4Og8Y8LvhizpTjoHxm9x3iV72
UDELcJ+YrqyJCTe2flUcy96o7Pbn50GXnwgtYD6WAW6IUszyn2ITgYIhu4wzZEt6
s6O7AoGAPTKbRA87L34LMlXyUBJma+etMARIP1zu8bXJ7hSJeMcog8zaLczN7ruT
pGAaLxggvtvuncMuTrG+cdmsR9SafSFKRS92NCxhOUonQ+NP6mLskIGzJZoQ5JvQ
qGzRVIDGbNkrVHM0IsAtHRpC0rYrtZY+9OwiraGcsqUMLwwQdCA=
-----END RSA PRIVATE KEY-----`

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

	err = os.WriteFile("validrsa1.key", []byte(validrsa1), 0600)
	if err != nil {
		t.Fatal(err)
	}

	keys, err := cosign.ImportKeyPair("validrsa1.key", passFunc)
	if err != nil {
		t.Fatal(err)
	}

	privKeyPath := filepath.Join(td, "import-cosign.key")
	if err := os.WriteFile(privKeyPath, keys.PrivateBytes, 0600); err != nil {
		t.Fatal(err)
	}

	pubKeyPath := filepath.Join(td, "import-cosign.pub")
	if err := os.WriteFile(pubKeyPath, keys.PublicBytes, 0600); err != nil {
		t.Fatal(err)
	}
	return keys, privKeyPath, pubKeyPath

}

func mockStdin(contents, td string, t *testing.T) func() {
	origin := os.Stdin

	p := mkfile(contents, td, t)
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = f

	return func() { os.Stdin = origin }
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

func mkfileWithExt(contents, td, ext string, t *testing.T) string {
	f := mkfile(contents, td, t)
	newName := f + ext
	err := os.Rename(f, newName)
	if err != nil {
		t.Fatal(err)
	}
	return newName
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

func mkimageindex(t *testing.T, n string) (name.Reference, *remote.Descriptor, func()) {
	ref, err := name.ParseReference(n, name.WeakValidation)
	if err != nil {
		t.Fatal(err)
	}
	ii, err := random.Index(512, 5, 4)
	if err != nil {
		t.Fatal(err)
	}

	regClientOpts := registryClientOpts(context.Background())

	if err := remote.WriteIndex(ref, ii, regClientOpts...); err != nil {
		t.Fatal(err)
	}

	remoteIndex, err := remote.Get(ref, regClientOpts...)
	if err != nil {
		t.Fatal(err)
	}

	cleanup := func() {
		_ = remote.Delete(ref, regClientOpts...)
		ref, _ := ociremote.SignatureTag(ref.Context().Digest(remoteIndex.Descriptor.Digest.String()), ociremote.WithRemoteOptions(regClientOpts...))
		_ = remote.Delete(ref, regClientOpts...)
	}
	return ref, remoteIndex, cleanup
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
