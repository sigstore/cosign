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
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/secure-systems-lab/go-securesystemslib/encrypted"

	// Initialize all known client auth plugins
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	cliverify "github.com/sigstore/cosign/v3/cmd/cosign/cli/verify"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/cosign/env"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	sigs "github.com/sigstore/cosign/v3/pkg/signature"
	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore/pkg/signature"
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

var verifyCertChain = func(keyRef, certChain, certFile, imageRef string, checkClaims bool, annotations map[string]interface{}, attachment string, skipTlogVerify bool) error {
	cmd := cliverify.VerifyCommand{
		KeyRef:        keyRef,
		RekorURL:      rekorURL,
		CheckClaims:   checkClaims,
		Annotations:   sigs.AnnotationsMap{Annotations: annotations},
		Attachment:    attachment,
		HashAlgorithm: crypto.SHA256,
		MaxWorkers:    10,
		IgnoreTlog:    skipTlogVerify,
		CertVerifyOptions: options.CertVerifyOptions{
			Cert:      certFile,
			CertChain: certChain,
		},
	}

	args := []string{imageRef}

	return cmd.Exec(context.Background(), args)
}

var verifyCertBundle = func(keyRef, caCertFile, caIntermediateCertFile, imageRef string, checkClaims bool, annotations map[string]interface{}, attachment string, skipTlogVerify bool) error {
	cmd := cliverify.VerifyCommand{
		KeyRef:        keyRef,
		RekorURL:      rekorURL,
		CheckClaims:   checkClaims,
		Annotations:   sigs.AnnotationsMap{Annotations: annotations},
		Attachment:    attachment,
		HashAlgorithm: crypto.SHA256,
		MaxWorkers:    10,
		IgnoreTlog:    skipTlogVerify,
		CertVerifyOptions: options.CertVerifyOptions{
			CAIntermediates:      caIntermediateCertFile,
			CARoots:              caCertFile,
			CertOidcIssuerRegexp: ".*",
			CertIdentityRegexp:   ".*",
		},
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

var verifyKeylessTSA = func(imageRef string, tsaCertChain string, skipSCT bool, skipTlogVerify bool) error { //nolint: unused
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

var verifyKeylessTSAWithCARoots = func(imageRef string,
	caroots string, // filename of a PEM file with CA Roots certificates
	intermediates string, // empty or filename of a PEM file with Intermediate certificates
	certFile string, // filename of a PEM file with the codesigning certificate
	tsaCertChain string,
	skipSCT bool,
	skipTlogVerify bool) error {
	cmd := cliverify.VerifyCommand{
		CertVerifyOptions: options.CertVerifyOptions{
			CertOidcIssuerRegexp: ".*",
			CertIdentityRegexp:   ".*",
		},
		CertRef:          certFile,
		CARoots:          caroots,
		CAIntermediates:  intermediates,
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

var verifyBlobKeylessWithCARoots = func(blobRef string,
	sig string,
	caroots string, // filename of a PEM file with CA Roots certificates
	intermediates string, // empty or filename of a PEM file with Intermediate certificates
	certFile string, // filename of a PEM file with the codesigning certificate
	skipSCT bool,
	skipTlogVerify bool) error {
	cmd := cliverify.VerifyBlobCmd{
		CertVerifyOptions: options.CertVerifyOptions{
			CertOidcIssuerRegexp: ".*",
			CertIdentityRegexp:   ".*",
		},
		SigRef:          sig,
		CertRef:         certFile,
		CARoots:         caroots,
		CAIntermediates: intermediates,
		IgnoreSCT:       skipSCT,
		IgnoreTlog:      skipTlogVerify,
	}
	return cmd.Exec(context.Background(), blobRef)
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

func keypairWithAlgorithm(t *testing.T, td string, publicKeyDetails v1.PublicKeyDetails) (*cosign.KeysBytes, string, string) {
	algo, err := signature.GetAlgorithmDetails(publicKeyDetails)
	if err != nil {
		t.Fatal(err)
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(td); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()
	keys, err := cosign.GenerateKeyPairWithAlgorithm(&algo, passFunc)
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

func keypair(t *testing.T, td string) (*cosign.KeysBytes, string, string) {
	return keypairWithAlgorithm(t, td, v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256)
}

// convert the given ecdsa.PrivateKey to a PEM encoded string, import into sigstore format,
// and write to the given file path. Returns the path to the imported key (<td>/<fname>)
func importECDSAPrivateKey(t *testing.T, privKey *ecdsa.PrivateKey, td, fname string) string {
	t.Helper()
	x509Encoded, _ := x509.MarshalPKCS8PrivateKey(privKey)
	encBytes, _ := encrypted.Encrypt(x509Encoded, keyPass)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  cosign.CosignPrivateKeyPemType,
		Bytes: encBytes})

	cosignKeyPath := filepath.Join(td, fname)
	if err := os.WriteFile(cosignKeyPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	return cosignKeyPath
}

func importSampleKeyPair(t *testing.T, td string) (*cosign.KeysBytes, string, string) {
	//nolint: gosec
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
		_ = os.Chdir(wd)
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

func mockStdin(contents, td string, t *testing.T) func() { //nolint: unused
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
		ref, _ := ociremote.SignatureTag(ref.Context().Digest(remoteImage.Digest.String()), ociremote.WithRemoteOptions(regClientOpts...))
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
		ref, _ := ociremote.SignatureTag(ref.Context().Digest(remoteIndex.Digest.String()), ociremote.WithRemoteOptions(regClientOpts...))
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
	repo := os.Getenv("COSIGN_TEST_REPO") //nolint: forbidigo
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

// setLocalEnv sets SIGSTORE_CT_LOG_PUBLIC_KEY_FILE, SIGSTORE_ROOT_FILE, and SIGSTORE_REKOR_PUBLIC_KEY for the locally running sigstore deployment.
func setLocalEnv(t *testing.T, dir string) error {
	ctLogKey := os.Getenv("CT_LOG_KEY") //nolint: forbidigo
	t.Setenv(env.VariableSigstoreCTLogPublicKeyFile.String(), ctLogKey)
	err := downloadAndSetEnv(t, fulcioURL+"/api/v1/rootCert", env.VariableSigstoreRootFile.String(), dir)
	if err != nil {
		return fmt.Errorf("error setting %s env var: %w", env.VariableSigstoreRootFile.String(), err)
	}
	err = downloadAndSetEnv(t, rekorURL+"/api/v1/log/publicKey", env.VariableSigstoreRekorPublicKey.String(), dir)
	if err != nil {
		return fmt.Errorf("error setting %s env var: %w", env.VariableSigstoreRekorPublicKey.String(), err)
	}
	return nil
}

// copyFile copies a file from a source to a destination.
func copyFile(src, dst string) error {
	f, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("error opening source file: %w", err)
	}
	defer f.Close()
	cp, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("error creating destination file: %w", err)
	}
	defer cp.Close()
	_, err = io.Copy(cp, f)
	if err != nil {
		return fmt.Errorf("error copying file: %w", err)
	}
	return nil
}

// downloadFile fetches a URL and stores it at the given file path.
func downloadFile(url string, fp *os.File) error {
	resp, err := http.Get(url) //nolint: gosec
	if err != nil {
		return fmt.Errorf("error downloading file: %w", err)
	}
	defer resp.Body.Close()
	_, err = io.Copy(fp, resp.Body)
	if err != nil {
		return fmt.Errorf("error writing to file: %w", err)
	}
	return nil
}

// downloadAndSetEnv fetches a URL and sets the given environment variable to point to the downloaded file path.
func downloadAndSetEnv(t *testing.T, url, envVar, dir string) error {
	f, err := os.CreateTemp(dir, "")
	if err != nil {
		return fmt.Errorf("error creating temp file: %w", err)
	}
	err = downloadFile(url, f)
	if err != nil {
		return fmt.Errorf("error downloading file: %w", err)
	}
	t.Setenv(envVar, f.Name())
	return nil
}

func generateCertificateBundleFiles(td string, genIntermediate bool, outputSuffix string) (
	caCertFile string,
	caPrivKeyFile string,
	caIntermediateCertFile string,
	caIntermediatePrivKeyFile string,
	certFile string,
	certChainFile string,
	err error,
) {
	caCertBuf, caPrivKeyBuf, caIntermediateCertBuf, caIntermediatePrivKeyBuf, certBuf, certChainBuf, err := generateCertificateBundle(genIntermediate)
	if err != nil {
		err = fmt.Errorf("error generating certificate bundle: %w", err)
		return
	}
	caCertFile = filepath.Join(td, fmt.Sprintf("caCert%s.pem", outputSuffix))
	err = os.WriteFile(caCertFile, caCertBuf.Bytes(), 0600)
	if err != nil {
		err = fmt.Errorf("error writing caCert to file %s: %w", caCertFile, err)
		return
	}
	caPrivKeyFile = filepath.Join(td, fmt.Sprintf("caPrivKey%s.pem", outputSuffix))
	err = os.WriteFile(caPrivKeyFile, caPrivKeyBuf.Bytes(), 0600)
	if err != nil {
		err = fmt.Errorf("error writing caPrivKey to file %s: %w", caPrivKeyFile, err)
		return
	}
	if genIntermediate {
		caIntermediateCertFile = filepath.Join(td, fmt.Sprintf("caIntermediateCert%s.pem", outputSuffix))
		err = os.WriteFile(caIntermediateCertFile, caIntermediateCertBuf.Bytes(), 0600)
		if err != nil {
			err = fmt.Errorf("error writing caIntermediateCert to file %s: %w", caIntermediateCertFile, err)
			return
		}
		caIntermediatePrivKeyFile = filepath.Join(td, fmt.Sprintf("caIntermediatePrivKey%s.pem", outputSuffix))
		err = os.WriteFile(caIntermediatePrivKeyFile, caIntermediatePrivKeyBuf.Bytes(), 0600)
		if err != nil {
			err = fmt.Errorf("error writing caIntermediatePrivKey to file %s: %w", caIntermediatePrivKeyFile, err)
			return
		}
	}
	certFile = filepath.Join(td, fmt.Sprintf("cert%s.pem", outputSuffix))
	err = os.WriteFile(certFile, certBuf.Bytes(), 0600)
	if err != nil {
		err = fmt.Errorf("error writing cert to file %s: %w", certFile, err)
		return
	}

	// write the contents of certChainBuf to a file
	certChainFile = filepath.Join(td, fmt.Sprintf("certchain%s.pem", outputSuffix))
	err = os.WriteFile(certChainFile, certChainBuf.Bytes(), 0600)
	if err != nil {
		err = fmt.Errorf("error writing certificate chain to file %s: %w", certFile, err)
		return
	}
	return
}

func generateCertificateBundle(genIntermediate bool) (
	caCertBuf *bytes.Buffer,
	caPrivKeyBuf *bytes.Buffer,
	caIntermediateCertBuf *bytes.Buffer,
	caIntermediatePrivKeyBuf *bytes.Buffer,
	certBuf *bytes.Buffer,
	certBundleBuf *bytes.Buffer,
	err error, //nolint: unparam
) {
	// set up our CA certificate
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:       []string{"CA Company, INC."},
			OrganizationalUnit: []string{"CA Root Team"},
			Country:            []string{"US"},
			Province:           []string{""},
			Locality:           []string{"San Francisco"},
			StreetAddress:      []string{"Golden Gate Bridge"},
			PostalCode:         []string{"94016"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning /*, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth */},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		EmailAddresses:        []string{"ca@example.com"},
	}

	// create our private and public key
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatal(err)
	}
	// create the CA
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		log.Fatal(err)
	}

	caCertBuf = &bytes.Buffer{}
	err = pem.Encode(caCertBuf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	if err != nil {
		log.Fatalf("unable to write PEM encode: %v", err)
	}

	caPrivKeyBuf = &bytes.Buffer{}
	err = pem.Encode(caPrivKeyBuf, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})
	if err != nil {
		log.Fatalf("unable to PEM encode private key to buffer: %v", err) //nolint:gocritic
	}

	// generate intermediate CA if requested
	var caIntermediate *x509.Certificate
	var caIntermediatePrivKey *rsa.PrivateKey
	if genIntermediate {
		caIntermediate = &x509.Certificate{
			SerialNumber: big.NewInt(2019),
			Subject: pkix.Name{
				Organization:       []string{"CA Company, INC."},
				OrganizationalUnit: []string{"CA Intermediate Team"},
				Country:            []string{"US"},
				Province:           []string{""},
				Locality:           []string{"San Francisco"},
				StreetAddress:      []string{"Golden Gate Bridge"},
				PostalCode:         []string{"94016"},
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(10, 0, 0),
			IsCA:                  true,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning /*, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth */},
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
			EmailAddresses:        []string{"ca@example.com"},
		}
		// create our private and public key
		caIntermediatePrivKey, err = rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			log.Fatal(err)
		}

		// create the Intermediate CA
		caIntermediateBytes, err := x509.CreateCertificate(rand.Reader, caIntermediate, ca, &caIntermediatePrivKey.PublicKey, caPrivKey)
		if err != nil {
			log.Fatal(err)
		}

		caIntermediateCertBuf = &bytes.Buffer{}
		err = pem.Encode(caIntermediateCertBuf, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: caIntermediateBytes,
		})
		if err != nil {
			log.Fatalf("unable to write to buffer: %v", err)
		}
		caIntermediatePrivKeyBuf = &bytes.Buffer{}
		err = pem.Encode(caIntermediatePrivKeyBuf, &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(caIntermediatePrivKey),
		})
		if err != nil {
			log.Fatalf("unable to PEM encode caIntermediatePrivKey: %v", err)
		}
	}
	// set up our server certificate
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:       []string{"End User"},
			OrganizationalUnit: []string{"End Node Team"},
			Country:            []string{"US"},
			Province:           []string{""},
			Locality:           []string{"San Francisco"},
			StreetAddress:      []string{"Golden Gate Bridge"},
			PostalCode:         []string{"94016"},
		},
		IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().AddDate(10, 0, 0),
		SubjectKeyId:   []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning /* x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth */},
		KeyUsage:       x509.KeyUsageDigitalSignature,
		EmailAddresses: []string{"xyz@nosuchprovider.com"},
		DNSNames:       []string{"next.hugeunicorn.xyz"},
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatal(err)
	}

	var certBytes []byte
	if !genIntermediate {
		certBytes, err = x509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, caPrivKey)
	} else {
		certBytes, err = x509.CreateCertificate(rand.Reader, cert, caIntermediate, &caIntermediatePrivKey.PublicKey, caIntermediatePrivKey)
	}
	if err != nil {
		log.Fatal(err)
	}

	certBuf = &bytes.Buffer{}
	err = pem.Encode(certBuf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		log.Fatalf("failed to encode cert: %v", err)
	}

	// concatenate into certChainBuf the contents of caIntermediateCertBuf and caCertBuf
	certBundleBuf = &bytes.Buffer{}
	if genIntermediate {
		_, err = certBundleBuf.Write(caIntermediateCertBuf.Bytes())
		if err != nil {
			log.Fatalf("failed to write caIntermediateCertBuf to certChainBuf: %v", err)
		}
	}
	_, err = certBundleBuf.Write(caCertBuf.Bytes())
	if err != nil {
		log.Fatalf("failed to write caCertBuf to certChainBuf: %v", err)
	}

	return caCertBuf, caPrivKeyBuf, caIntermediateCertBuf, caIntermediatePrivKeyBuf, certBuf, certBundleBuf, nil
}
