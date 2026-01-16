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

//go:build e2e && !cross && !kms && !registry

package test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/stretchr/testify/assert"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	// Initialize all known client auth plugins
	"github.com/sigstore/cosign/v3/cmd/cosign/cli"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/attach"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/attest"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/dockerfile"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/download"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/initialize"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/manifest"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/publickey"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/signingconfig"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/trustedroot"
	cliverify "github.com/sigstore/cosign/v3/cmd/cosign/cli/verify"
	"github.com/sigstore/cosign/v3/internal/pkg/cosign/fulcio/fulcioroots"
	"github.com/sigstore/cosign/v3/internal/pkg/cosign/tsa"
	"github.com/sigstore/cosign/v3/internal/pkg/cosign/tsa/client"
	cert_test "github.com/sigstore/cosign/v3/internal/test"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v3/pkg/cosign/env"
	"github.com/sigstore/cosign/v3/pkg/cosign/kubernetes"
	"github.com/sigstore/cosign/v3/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	sigs "github.com/sigstore/cosign/v3/pkg/signature"
	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/payload"
	tsaclient "github.com/sigstore/timestamp-authority/v2/pkg/client"
	"github.com/sigstore/timestamp-authority/v2/pkg/server"
	"github.com/spf13/viper"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

func TestSignVerify(t *testing.T) {
	td := t.TempDir()
	err := downloadAndSetEnv(t, rekorURL+"/api/v1/log/publicKey", env.VariableSigstoreRekorPublicKey.String(), td)
	if err != nil {
		t.Fatal(err)
	}

	repo, stop := reg(t)
	defer stop()

	imgName := path.Join(repo, "cosign-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, pubKeyPath := keypair(t, td)

	ctx := context.Background()
	// Verify should fail at first
	mustErr(verify(pubKeyPath, imgName, true, nil, "", false), t)
	// So should download
	mustErr(download.SignatureCmd(ctx, options.RegistryOptions{}, imgName, os.Stdout), t)

	// Now sign the image
	ko := options.KeyOpts{
		KeyRef:           privKeyPath,
		PassFunc:         passFunc,
		RekorURL:         rekorURL,
		SkipConfirmation: true,
	}
	so := options.SignOptions{
		Upload:     true,
		TlogUpload: true,
	}
	must(sign.SignCmd(ctx, ro, ko, so, []string{imgName}), t)

	// Now verify and download should work!
	must(verify(pubKeyPath, imgName, true, nil, "", false), t)
	must(download.SignatureCmd(ctx, options.RegistryOptions{}, imgName, os.Stdout), t)

	// Ensure it verifies if you default to the new protobuf bundle format
	cmd := cliverify.VerifyCommand{
		KeyRef:          pubKeyPath,
		RekorURL:        rekorURL,
		NewBundleFormat: true,
	}
	must(cmd.Exec(ctx, []string{imgName}), t)

	// Look for a specific annotation
	mustErr(verify(pubKeyPath, imgName, true, map[string]interface{}{"foo": "bar"}, "", false), t)

	so.AnnotationOptions = options.AnnotationOptions{
		Annotations: []string{"foo=bar"},
	}
	// Sign the image with an annotation
	must(sign.SignCmd(ctx, ro, ko, so, []string{imgName}), t)

	// It should match this time.
	must(verify(pubKeyPath, imgName, true, map[string]interface{}{"foo": "bar"}, "", false), t)

	// But two doesn't work
	mustErr(verify(pubKeyPath, imgName, true, map[string]interface{}{"foo": "bar", "baz": "bat"}, "", false), t)
}

func TestSignVerifyCertBundle(t *testing.T) {
	td := t.TempDir()
	err := downloadAndSetEnv(t, rekorURL+"/api/v1/log/publicKey", env.VariableSigstoreRekorPublicKey.String(), td)
	if err != nil {
		t.Fatal(err)
	}

	repo, stop := reg(t)
	defer stop()

	imgName := path.Join(repo, "cosign-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, pubKeyPath := keypair(t, td)
	caCertFile, _ /* caPrivKeyFile */, caIntermediateCertFile, _ /* caIntermediatePrivKeyFile */, certFile, certChainFile, err := generateCertificateBundleFiles(td, true, "foobar")
	must(err, t)

	ctx := context.Background()
	// Verify should fail at first
	mustErr(verifyCertBundle(pubKeyPath, caCertFile, caIntermediateCertFile, imgName, true, nil, "", true), t)
	// So should download
	mustErr(download.SignatureCmd(ctx, options.RegistryOptions{}, imgName, os.Stdout), t)

	// Now sign the image
	ko := options.KeyOpts{
		KeyRef:           privKeyPath,
		PassFunc:         passFunc,
		RekorURL:         rekorURL,
		SkipConfirmation: true,
	}
	so := options.SignOptions{
		Upload:     true,
		TlogUpload: true,
	}
	must(sign.SignCmd(ctx, ro, ko, so, []string{imgName}), t)

	// Now verify and download should work!
	ignoreTlog := true
	must(verifyCertBundle(pubKeyPath, caCertFile, caIntermediateCertFile, imgName, true, nil, "", ignoreTlog), t)
	// verification with certificate chain instead of root/intermediate files should work as well
	must(verifyCertChain(pubKeyPath, certChainFile, certFile, imgName, true, nil, "", ignoreTlog), t)
	must(download.SignatureCmd(ctx, options.RegistryOptions{}, imgName, os.Stdout), t)

	// Look for a specific annotation
	mustErr(verifyCertBundle(pubKeyPath, caCertFile, caIntermediateCertFile, imgName, true, map[string]interface{}{"foo": "bar"}, "", ignoreTlog), t)

	so.AnnotationOptions = options.AnnotationOptions{
		Annotations: []string{"foo=bar"},
	}
	// Sign the image with an annotation
	must(sign.SignCmd(ctx, ro, ko, so, []string{imgName}), t)

	// It should match this time.
	must(verifyCertBundle(pubKeyPath, caCertFile, caIntermediateCertFile, imgName, true, map[string]interface{}{"foo": "bar"}, "", ignoreTlog), t)

	// But two doesn't work
	mustErr(verifyCertBundle(pubKeyPath, caCertFile, caIntermediateCertFile, imgName, true, map[string]interface{}{"foo": "bar", "baz": "bat"}, "", ignoreTlog), t)
}

func TestSignVerifyClean(t *testing.T) {
	td := t.TempDir()
	err := downloadAndSetEnv(t, rekorURL+"/api/v1/log/publicKey", env.VariableSigstoreRekorPublicKey.String(), td)
	if err != nil {
		t.Fatal(err)
	}

	repo, stop := reg(t)
	defer stop()

	imgName := path.Join(repo, "cosign-e2e")

	_, _, _ = mkimage(t, imgName)

	_, privKeyPath, pubKeyPath := keypair(t, td)

	ctx := context.Background()

	// Now sign the image
	ko := options.KeyOpts{
		KeyRef:           privKeyPath,
		PassFunc:         passFunc,
		RekorURL:         rekorURL,
		SkipConfirmation: true,
	}
	so := options.SignOptions{
		Upload:     true,
		TlogUpload: true,
	}
	must(sign.SignCmd(ctx, ro, ko, so, []string{imgName}), t)

	// Now verify and download should work!
	must(verify(pubKeyPath, imgName, true, nil, "", false), t)
	must(download.SignatureCmd(ctx, options.RegistryOptions{}, imgName, os.Stdout), t)

	// Now clean signature from the given image
	must(cli.CleanCmd(ctx, options.RegistryOptions{}, "all", imgName, true), t)

	// It doesn't work
	mustErr(verify(pubKeyPath, imgName, true, nil, "", false), t)
}

func TestImportSignVerifyClean(t *testing.T) {
	td := t.TempDir()
	err := downloadAndSetEnv(t, rekorURL+"/api/v1/log/publicKey", env.VariableSigstoreRekorPublicKey.String(), td)
	if err != nil {
		t.Fatal(err)
	}

	repo, stop := reg(t)
	defer stop()

	imgName := path.Join(repo, "cosign-e2e")

	_, _, _ = mkimage(t, imgName)

	_, privKeyPath, pubKeyPath := importSampleKeyPair(t, td)

	ctx := context.Background()

	// Now sign the image
	ko := options.KeyOpts{
		KeyRef:           privKeyPath,
		PassFunc:         passFunc,
		RekorURL:         rekorURL,
		SkipConfirmation: true,
	}
	so := options.SignOptions{
		Upload:     true,
		TlogUpload: true,
	}
	must(sign.SignCmd(ctx, ro, ko, so, []string{imgName}), t)

	// Now verify and download should work!
	must(verify(pubKeyPath, imgName, true, nil, "", false), t)
	must(download.SignatureCmd(ctx, options.RegistryOptions{}, imgName, os.Stdout), t)

	// Now clean signature from the given image
	must(cli.CleanCmd(ctx, options.RegistryOptions{}, "all", imgName, true), t)

	// It doesn't work
	mustErr(verify(pubKeyPath, imgName, true, nil, "", false), t)

	// Sign with new bundle format
	so.NewBundleFormat = true
	must(sign.SignCmd(ctx, ro, ko, so, []string{imgName}), t)

	// Verify should work again
	trustedRootPath := prepareTrustedRoot(t, "")
	bundleVerifyCmd := cliverify.VerifyCommand{
		CommonVerifyOptions: options.CommonVerifyOptions{
			TrustedRootPath: trustedRootPath,
		},
		KeyRef:              pubKeyPath,
		NewBundleFormat:     true,
		UseSignedTimestamps: false,
	}
	must(bundleVerifyCmd.Exec(ctx, []string{imgName}), t)

	// Clean again
	must(cli.CleanCmd(ctx, options.RegistryOptions{}, "all", imgName, true), t)

	// Verify should fail again
	mustErr(bundleVerifyCmd.Exec(ctx, []string{imgName}), t)
}

type targetInfo struct {
	name   string
	source string
	usage  string
}

func downloadTargets(td string, targets []targetInfo, targetsMeta *metadata.Metadata[metadata.TargetsType]) error {
	targetsDir := filepath.Join(td, "targets")
	err := os.RemoveAll(targetsDir)
	if err != nil {
		return err
	}
	err = os.Mkdir(targetsDir, 0o700)
	if err != nil {
		return err
	}
	targetsMeta.Signed.Targets = make(map[string]*metadata.TargetFiles)
	for _, target := range targets {
		targetLocalPath := filepath.Join(targetsDir, target.name)
		if strings.HasPrefix(target.source, "http") {
			fp, err := os.Create(targetLocalPath)
			if err != nil {
				return err
			}
			defer fp.Close()
			err = downloadFile(target.source, fp)
			if err != nil {
				return err
			}
		}
		if strings.HasPrefix(target.source, "/") {
			err = copyFile(target.source, targetLocalPath)
			if err != nil {
				return err
			}
		}
		targetFileInfo, err := metadata.TargetFile().FromFile(targetLocalPath, "sha256")
		if err != nil {
			return err
		}
		if target.usage != "" {
			customMsg := fmt.Sprintf(`{"sigstore":{"usage": "%s"}}`, target.usage)
			custom := json.RawMessage([]byte(customMsg))
			targetFileInfo.Custom = &custom
		}
		targetsMeta.Signed.Targets[target.name] = targetFileInfo
	}
	return nil
}

type tuf struct {
	publicKey *metadata.Key
	signer    signature.Signer
	root      *metadata.Metadata[metadata.RootType]
	snapshot  *metadata.Metadata[metadata.SnapshotType]
	timestamp *metadata.Metadata[metadata.TimestampType]
	targets   *metadata.Metadata[metadata.TargetsType]
}

func newKey() (*metadata.Key, signature.Signer, error) {
	pub, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, err
	}
	public, err := metadata.KeyFromPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}
	signer, err := signature.LoadSigner(private, crypto.Hash(0))
	if err != nil {
		return nil, nil, err
	}
	return public, signer, nil
}

func newTUF(td string, targetList []targetInfo) (*tuf, error) {
	// source: https://github.com/theupdateframework/go-tuf/blob/v2.0.2/examples/repository/basic_repository.go
	expiration := time.Now().AddDate(0, 0, 1).UTC()
	targets := metadata.Targets(expiration)
	err := downloadTargets(td, targetList, targets)
	if err != nil {
		return nil, err
	}
	snapshot := metadata.Snapshot(expiration)
	timestamp := metadata.Timestamp(expiration)
	root := metadata.Root(expiration)
	root.Signed.ConsistentSnapshot = false

	public, signer, err := newKey()
	if err != nil {
		return nil, err
	}

	tuf := &tuf{
		publicKey: public,
		signer:    signer,
		root:      root,
		snapshot:  snapshot,
		timestamp: timestamp,
		targets:   targets,
	}
	for _, name := range []string{"targets", "snapshot", "timestamp", "root"} {
		err := tuf.root.Signed.AddKey(tuf.publicKey, name)
		if err != nil {
			return nil, err
		}
		switch name {
		case "targets":
			_, err = tuf.targets.Sign(tuf.signer)
		case "snapshot":
			_, err = tuf.snapshot.Sign(tuf.signer)
		case "timestamp":
			_, err = tuf.timestamp.Sign(tuf.signer)
		case "root":
			_, err = tuf.root.Sign(tuf.signer)
		}
		if err != nil {
			return nil, err
		}
	}
	err = tuf.targets.ToFile(filepath.Join(td, "targets.json"), false)
	if err != nil {
		return nil, err
	}
	err = tuf.snapshot.ToFile(filepath.Join(td, "snapshot.json"), false)
	if err != nil {
		return nil, err
	}
	err = tuf.timestamp.ToFile(filepath.Join(td, "timestamp.json"), false)
	if err != nil {
		return nil, err
	}
	err = tuf.root.ToFile(filepath.Join(td, fmt.Sprintf("%d.%s.json", tuf.root.Signed.Version, "root")), false)
	if err != nil {
		return nil, err
	}

	err = tuf.root.VerifyDelegate("root", tuf.root)
	if err != nil {
		return nil, err
	}
	err = tuf.root.VerifyDelegate("targets", tuf.targets)
	if err != nil {
		return nil, err
	}
	err = tuf.root.VerifyDelegate("snapshot", tuf.snapshot)
	if err != nil {
		return nil, err
	}
	err = tuf.root.VerifyDelegate("timestamp", tuf.timestamp)
	if err != nil {
		return nil, err
	}

	return tuf, nil
}

func (tr *tuf) update(td string, targetList []targetInfo) error {
	err := downloadTargets(td, targetList, tr.targets)
	if err != nil {
		return err
	}
	tr.targets.Signatures = make([]metadata.Signature, 0)
	tr.targets.Signed.Version++
	_, err = tr.targets.Sign(tr.signer)
	if err != nil {
		return err
	}
	tr.snapshot.Signatures = make([]metadata.Signature, 0)
	tr.snapshot.Signed.Meta["targets.json"].Version++
	tr.snapshot.Signed.Version++
	tr.snapshot.Sign(tr.signer)
	tr.timestamp.Signatures = make([]metadata.Signature, 0)
	tr.timestamp.Signed.Meta["snapshot.json"].Version++
	tr.timestamp.Signed.Version++
	tr.timestamp.Sign(tr.signer)
	err = tr.targets.ToFile(filepath.Join(td, "targets.json"), false)
	if err != nil {
		return err
	}
	err = tr.snapshot.ToFile(filepath.Join(td, "snapshot.json"), false)
	if err != nil {
		return err
	}
	err = tr.timestamp.ToFile(filepath.Join(td, "timestamp.json"), false)
	if err != nil {
		return err
	}
	return nil
}

func downloadTSACerts(downloadDirectory string, tsaServer string) (string, string, string, error) {
	resp, err := http.Get(tsaServer + "/api/v1/timestamp/certchain")
	if err != nil {
		return "", "", "", err
	}
	defer resp.Body.Close()
	buffer := new(bytes.Buffer)
	buffer.ReadFrom(resp.Body)
	b := buffer.Bytes()
	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(b)
	if err != nil {
		return "", "", "", err
	}
	leaves := make([]*x509.Certificate, 0)
	intermediates := make([]*x509.Certificate, 0)
	roots := make([]*x509.Certificate, 0)
	for _, cert := range certs {
		if !cert.IsCA {
			leaves = append(leaves, cert)
		} else {
			// root certificates are self-signed
			if bytes.Equal(cert.RawSubject, cert.RawIssuer) {
				roots = append(roots, cert)
			} else {
				intermediates = append(intermediates, cert)
			}
		}
	}
	if len(leaves) != 1 {
		return "", "", "", fmt.Errorf("unexpected number of certificate leaves")
	}
	if len(roots) != 1 {
		return "", "", "", fmt.Errorf("unexpected number of certificate roots")
	}
	leafPath := filepath.Join(downloadDirectory, "tsa_leaf.crt.pem")
	leafFP, err := os.Create(leafPath)
	if err != nil {
		return "", "", "", err
	}
	defer leafFP.Close()
	err = pem.Encode(leafFP, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: leaves[0].Raw,
	})
	if err != nil {
		return "", "", "", err
	}
	rootPath := filepath.Join(downloadDirectory, "tsa_root.crt.pem")
	rootFP, err := os.Create(rootPath)
	if err != nil {
		return "", "", "", err
	}
	defer rootFP.Close()
	err = pem.Encode(rootFP, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: roots[0].Raw,
	})
	if err != nil {
		return "", "", "", err
	}
	intermediatePath := filepath.Join(downloadDirectory, "tsa_intermediate_0.crt.pem")
	intermediateFP, err := os.Create(intermediatePath)
	if err != nil {
		return "", "", "", err
	}
	defer intermediateFP.Close()
	intermediateBuffer := new(bytes.Buffer)
	for _, i := range intermediates {
		_, err = intermediateBuffer.Write(i.Raw)
		if err != nil {
			return "", "", "", err
		}
	}
	err = pem.Encode(intermediateFP, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: intermediateBuffer.Bytes(),
	})
	if err != nil {
		return "", "", "", err
	}
	return leafPath, intermediatePath, rootPath, nil
}

func trustedRootCmd(t *testing.T, downloadDirectory, tsaURL string) *trustedroot.CreateCmd {
	caPath := filepath.Join(downloadDirectory, "fulcio.crt.pem")
	caFP, err := os.Create(caPath)
	must(err, t)
	defer caFP.Close()
	must(downloadFile(fulcioURL+"/api/v1/rootCert", caFP), t)
	rekorPath := filepath.Join(downloadDirectory, "rekor.pub")
	rekorFP, err := os.Create(rekorPath)
	must(err, t)
	defer rekorFP.Close()
	must(downloadFile(rekorURL+"/api/v1/log/publicKey", rekorFP), t)
	ctfePath := filepath.Join(downloadDirectory, "ctfe.pub")
	home, err := os.UserHomeDir()
	must(err, t)
	must(copyFile(filepath.Join(home, "fulcio", "config", "ctfe", "pubkey.pem"), ctfePath), t)
	out := filepath.Join(downloadDirectory, "trusted_root.json")
	cmd := &trustedroot.CreateCmd{
		CertChain:    []string{caPath},
		CtfeKeyPath:  []string{ctfePath},
		Out:          out,
		RekorKeyPath: []string{rekorPath},
	}
	if tsaURL != "" {
		tsaPath := filepath.Join(downloadDirectory, "tsa.crt.pem")
		tsaFP, err := os.Create(tsaPath)
		must(err, t)
		must(downloadFile(tsaURL+"/api/v1/timestamp/certchain", tsaFP), t)
		cmd.TSACertChainPath = []string{tsaPath}
	}
	return cmd
}

func prepareTrustedRoot(t *testing.T, tsaURL string) string {
	downloadDirectory := t.TempDir()
	cmd := trustedRootCmd(t, downloadDirectory, tsaURL)
	must(cmd.Exec(context.TODO()), t)
	return cmd.Out
}

func prepareTrustedRootWithSelfSignedCertificate(t *testing.T, certPath, tsaURL string) string {
	td := t.TempDir()
	cmd := trustedRootCmd(t, td, tsaURL)
	cmd.CertChain = append(cmd.CertChain, certPath)
	must(cmd.Exec(context.TODO()), t)
	return cmd.Out
}

func TestSignVerifyWithTUFMirror(t *testing.T) {
	home, err := os.UserHomeDir() // fulcio repo was downloaded to $HOME in e2e_test.sh
	must(err, t)
	tufLocalCache := t.TempDir()
	t.Setenv("TUF_ROOT", tufLocalCache)
	tufMirror := t.TempDir()
	viper.Set("timestamp-signer", "memory")
	viper.Set("timestamp-signer-hash", "sha256")
	tsaAPIServer := server.NewRestAPIServer("localhost", 0, []string{"http"}, false, 10*time.Second, 10*time.Second)
	tsaServer := httptest.NewServer(tsaAPIServer.GetHandler())
	t.Cleanup(tsaServer.Close)
	tufServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.FileServer(http.Dir(tufMirror)).ServeHTTP(w, r)
	}))
	mirror := tufServer.URL
	tsaLeaf, tsaInter, tsaRoot, err := downloadTSACerts(t.TempDir(), tsaServer.URL)
	must(err, t)
	trustedRoot := prepareTrustedRoot(t, tsaServer.URL)
	tests := []struct {
		name          string
		targets       []targetInfo
		wantSignErr   bool
		wantVerifyErr bool
	}{
		{
			name: "invalid CT key name with no usage",
			targets: []targetInfo{
				{
					name:   "ct.pub",
					source: filepath.Join(home, "fulcio", "config", "ctfe", "pubkey.pem"),
				},
			},
			wantSignErr: true,
		},
		{
			name: "standard key names",
			targets: []targetInfo{
				{
					name:   "rekor.pub",
					source: rekorURL + "/api/v1/log/publicKey",
				},
				{
					name:   "fulcio.crt.pem",
					source: fulcioURL + "/api/v1/rootCert",
				},
				{
					name:   "ctfe.pub",
					source: filepath.Join(home, "fulcio", "config", "ctfe", "pubkey.pem"),
				},
				{
					name:   "tsa_leaf.crt.pem",
					source: tsaLeaf,
				},
				{
					name:   "tsa_root.crt.pem",
					source: tsaRoot,
				},
				{
					name:   "tsa_intermediate_0.crt.pem",
					source: tsaInter,
				},
			},
		},
		{
			name: "invalid verifier key names with no usage",
			targets: []targetInfo{
				{
					name:   "tlog.pubkey",
					source: rekorURL + "/api/v1/log/publicKey",
				},
				{
					name:   "ca.cert",
					source: fulcioURL + "/api/v1/rootCert",
				},
				{
					name:   "ctfe.pub",
					source: filepath.Join(home, "fulcio", "config", "ctfe", "pubkey.pem"),
				},
				{
					name:   "tsaleaf.pem",
					source: tsaLeaf,
				},
				{
					name:   "tsaca.pem",
					source: tsaRoot,
				},
				{
					name:   "tsachain.pem",
					source: tsaInter,
				},
			},
			wantVerifyErr: true,
		},
		{
			name: "nonstandard key names with valid usage",
			targets: []targetInfo{
				{
					name:   "tlog.pubkey",
					usage:  "Rekor",
					source: rekorURL + "/api/v1/log/publicKey",
				},
				{
					name:   "ca.cert",
					usage:  "Fulcio",
					source: fulcioURL + "/api/v1/rootCert",
				},
				{
					name:   "intermediate.cert",
					usage:  "Fulcio",
					source: fulcioURL + "/api/v1/rootCert",
				},
				{
					name:   "cert-transparency.pem",
					usage:  "CTFE",
					source: filepath.Join(home, "fulcio", "config", "ctfe", "pubkey.pem"),
				},
				{
					name:   "tsaleaf.pem",
					source: tsaLeaf,
					usage:  "TSA",
				},
				{
					name:   "tsaca.pem",
					source: tsaRoot,
					usage:  "TSA",
				},
				{
					name:   "tsachain.pem",
					source: tsaInter,
					usage:  "TSA",
				},
			},
		},
		{
			name: "trusted root",
			targets: []targetInfo{
				{
					name:   "trusted_root.json",
					source: trustedRoot,
				},
			},
		},
	}
	tuf, err := newTUF(tufMirror, tests[0].targets)
	must(err, t)
	for i, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			if i > 0 {
				must(tuf.update(tufMirror, test.targets), t)
			}
			rootPath := filepath.Join(tufMirror, "1.root.json")
			must(initialize.DoInitialize(ctx, rootPath, mirror), t)

			identityToken, err := getOIDCToken()
			if err != nil {
				t.Fatal(err)
			}

			// Sign an image
			repo, stop := reg(t)
			defer stop()
			imgName := path.Join(repo, "cosign-e2e-tuf")
			_, _, cleanup := mkimage(t, imgName)
			defer cleanup()

			ko := options.KeyOpts{
				FulcioURL:        fulcioURL,
				RekorURL:         rekorURL,
				IDToken:          identityToken,
				SkipConfirmation: true,
				TSAServerURL:     tsaServer.URL + "/api/v1/timestamp",
			}
			trustedMaterial, err := cosign.TrustedRoot()
			if err == nil {
				ko.TrustedMaterial = trustedMaterial
			}
			so := options.SignOptions{
				Upload:           true,
				TlogUpload:       true,
				SkipConfirmation: true,
			}
			gotErr := sign.SignCmd(ctx, ro, ko, so, []string{imgName})
			if test.wantSignErr {
				mustErr(gotErr, t)
				return
			}
			must(gotErr, t)

			// Verify an image
			issuer := os.Getenv("OIDC_URL")
			verifyCmd := cliverify.VerifyCommand{
				CertVerifyOptions: options.CertVerifyOptions{
					CertOidcIssuer: issuer,
					CertIdentity:   certID,
				},
				Offline:             true,
				CheckClaims:         true,
				UseSignedTimestamps: true,
			}
			gotErr = verifyCmd.Exec(ctx, []string{imgName})
			if test.wantVerifyErr {
				mustErr(gotErr, t)
			} else {
				must(gotErr, t)
			}

			// Sign a blob
			blob := "someblob"
			blobDir := t.TempDir()
			bp := filepath.Join(blobDir, blob)
			if err := os.WriteFile(bp, []byte(blob), 0o644); err != nil {
				t.Fatal(err)
			}
			tsPath := filepath.Join(blobDir, "ts.txt")
			bundlePath := filepath.Join(blobDir, "bundle.sig")
			// TODO(cmurphy): make this work with ko.NewBundleFormat = true
			ko.BundlePath = bundlePath
			ko.RFC3161TimestampPath = tsPath
			_, gotErr = sign.SignBlobCmd(ctx, ro, ko, bp, "", "", true, "", "", true)
			if test.wantSignErr {
				mustErr(gotErr, t)
			} else {
				must(gotErr, t)
			}

			// Verify a blob
			verifyBlobCmd := cliverify.VerifyBlobCmd{
				KeyOpts: ko,
				CertVerifyOptions: options.CertVerifyOptions{
					CertOidcIssuer: issuer,
					CertIdentity:   certID,
				},
				Offline:             true,
				UseSignedTimestamps: true,
			}
			gotErr = verifyBlobCmd.Exec(ctx, bp)
			if test.wantVerifyErr {
				mustErr(gotErr, t)
			} else {
				must(gotErr, t)
			}
		})
	}
}

func prepareSigningConfig(t *testing.T, fulcioURL, rekorURL, oidcURL, tsaURL string) string { //nolint: unparam
	startTime := "2024-01-01T00:00:00Z"
	fulcioSpec := fmt.Sprintf("url=%s,api-version=1,operator=fulcio-op,start-time=%s", fulcioURL, startTime)
	rekorSpec := fmt.Sprintf("url=%s,api-version=1,operator=rekor-op,start-time=%s", rekorURL, startTime)
	oidcSpec := fmt.Sprintf("url=%s,api-version=1,operator=oidc-op,start-time=%s", oidcURL, startTime)
	tsaSpec := fmt.Sprintf("url=%s,api-version=1,operator=tsa-op,start-time=%s", tsaURL, startTime)

	downloadDirectory := t.TempDir()
	out := filepath.Join(downloadDirectory, "signing_config.v0.2.json")
	cmd := &signingconfig.CreateCmd{
		FulcioSpecs:       []string{fulcioSpec},
		RekorSpecs:        []string{rekorSpec},
		OIDCProviderSpecs: []string{oidcSpec},
		TSASpecs:          []string{tsaSpec},
		RekorConfig:       "EXACT:1",
		TSAConfig:         "ANY",
		Out:               out,
	}
	must(cmd.Exec(context.TODO()), t)
	return out
}

func TestSignAttestVerifyBlobWithSigningConfig(t *testing.T) {
	tufLocalCache := t.TempDir()
	t.Setenv("TUF_ROOT", tufLocalCache)
	tufMirror := t.TempDir()
	viper.Set("timestamp-signer", "memory")
	viper.Set("timestamp-signer-hash", "sha256")
	tsaAPIServer := server.NewRestAPIServer("localhost", 0, []string{"http"}, false, 10*time.Second, 10*time.Second)
	tsaServer := httptest.NewServer(tsaAPIServer.GetHandler())
	t.Cleanup(tsaServer.Close)
	tufServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.FileServer(http.Dir(tufMirror)).ServeHTTP(w, r)
	}))
	mirror := tufServer.URL
	trustedRoot := prepareTrustedRoot(t, tsaServer.URL)
	signingConfigStr := prepareSigningConfig(t, fulcioURL, rekorURL, "unused", tsaServer.URL+"/api/v1/timestamp")
	sc, err := os.ReadFile(signingConfigStr)
	must(err, t)
	fmt.Println(string(sc))
	fmt.Println(fulcioURL)

	_, err = newTUF(tufMirror, []targetInfo{
		{
			name:   "trusted_root.json",
			source: trustedRoot,
		},
		{
			name:   "signing_config.v0.2.json",
			source: signingConfigStr,
		},
	})
	must(err, t)

	ctx := context.Background()

	rootPath := filepath.Join(tufMirror, "1.root.json")
	must(initialize.DoInitialize(ctx, rootPath, mirror), t)

	identityToken, err := getOIDCToken()
	if err != nil {
		t.Fatal(err)
	}

	ko := options.KeyOpts{
		IDToken:          identityToken,
		SkipConfirmation: true,
	}
	trustedMaterial, err := cosign.TrustedRoot()
	must(err, t)
	ko.TrustedMaterial = trustedMaterial
	signingConfig, err := cosign.SigningConfig()
	must(err, t)
	ko.SigningConfig = signingConfig

	// Sign a blob
	blob := "someblob"
	blobDir := t.TempDir()
	bp := filepath.Join(blobDir, blob)
	if err := os.WriteFile(bp, []byte(blob), 0o644); err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(blobDir, "bundle.json")
	ko.NewBundleFormat = true
	ko.BundlePath = bundlePath

	_, err = sign.SignBlobCmd(ctx, ro, ko, bp, "", "", false, "", "", true)
	must(err, t)

	// Verify a blob
	issuer := os.Getenv("OIDC_URL")
	verifyBlobCmd := cliverify.VerifyBlobCmd{
		KeyOpts: ko,
		CertVerifyOptions: options.CertVerifyOptions{
			CertOidcIssuer: issuer,
			CertIdentity:   certID,
		},
		UseSignedTimestamps: true,
	}
	err = verifyBlobCmd.Exec(ctx, bp)
	must(err, t)

	// Sign an attestation
	statement := `{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"someblob","digest":{"alg":"7e9b6e7ba2842c91cf49f3e214d04a7a496f8214356f41d81a6e6dcad11f11e3"}}],"predicateType":"something","predicate":{}}`
	attestDir := t.TempDir()
	statementPath := filepath.Join(attestDir, "statement")
	if err := os.WriteFile(statementPath, []byte(statement), 0o644); err != nil {
		t.Fatal(err)
	}
	attBundlePath := filepath.Join(attestDir, "attest.bundle.json")
	ko.NewBundleFormat = true
	ko.BundlePath = attBundlePath

	attestBlobCmd := attest.AttestBlobCommand{
		KeyOpts:        ko,
		RekorEntryType: "dsse",
		StatementPath:  statementPath,
		TlogUpload:     true,
	}
	must(attestBlobCmd.Exec(ctx, bp), t)

	// Verify an attestation
	verifyBlobAttestationCmd := cliverify.VerifyBlobAttestationCommand{
		KeyOpts: ko,
		CertVerifyOptions: options.CertVerifyOptions{
			CertOidcIssuer: issuer,
			CertIdentity:   certID,
		},
		UseSignedTimestamps: true,
		Digest:              "7e9b6e7ba2842c91cf49f3e214d04a7a496f8214356f41d81a6e6dcad11f11e3",
		DigestAlg:           "alg",
		CheckClaims:         true,
	}
	err = verifyBlobAttestationCmd.Exec(ctx, "")
	must(err, t)
}

func TestSignAttestVerifyContainerWithSigningConfig(t *testing.T) {
	tufLocalCache := t.TempDir()
	t.Setenv("TUF_ROOT", tufLocalCache)
	tufMirror := t.TempDir()
	viper.Set("timestamp-signer", "memory")
	viper.Set("timestamp-signer-hash", "sha256")
	tsaAPIServer := server.NewRestAPIServer("localhost", 0, []string{"http"}, false, 10*time.Second, 10*time.Second)
	tsaServer := httptest.NewServer(tsaAPIServer.GetHandler())
	t.Cleanup(tsaServer.Close)
	tufServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.FileServer(http.Dir(tufMirror)).ServeHTTP(w, r)
	}))
	mirror := tufServer.URL
	trustedRoot := prepareTrustedRoot(t, tsaServer.URL)
	signingConfigStr := prepareSigningConfig(t, fulcioURL, rekorURL, "unused", tsaServer.URL+"/api/v1/timestamp")

	_, err := newTUF(tufMirror, []targetInfo{
		{
			name:   "trusted_root.json",
			source: trustedRoot,
		},
		{
			name:   "signing_config.v0.2.json",
			source: signingConfigStr,
		},
	})
	must(err, t)

	repo, stop := reg(t)
	defer stop()
	imgName := path.Join(repo, "cosign-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	ctx := context.Background()

	rootPath := filepath.Join(tufMirror, "1.root.json")
	must(initialize.DoInitialize(ctx, rootPath, mirror), t)

	identityToken, err := getOIDCToken()
	if err != nil {
		t.Fatal(err)
	}

	ko := options.KeyOpts{
		IDToken:          identityToken,
		NewBundleFormat:  true,
		SkipConfirmation: true,
	}
	trustedMaterial, err := cosign.TrustedRoot()
	must(err, t)
	ko.TrustedMaterial = trustedMaterial
	signingConfig, err := cosign.SigningConfig()
	must(err, t)
	ko.SigningConfig = signingConfig

	// Sign image with identity token in bundle format
	so := options.SignOptions{
		Upload:          true,
		NewBundleFormat: true,
		TlogUpload:      true,
	}
	must(sign.SignCmd(ctx, ro, ko, so, []string{imgName}), t)

	// Verify Fulcio-signed image
	cmd := cliverify.VerifyCommand{
		CertVerifyOptions: options.CertVerifyOptions{
			CertOidcIssuer: os.Getenv("OIDC_URL"),
			CertIdentity:   certID,
		},
		NewBundleFormat:     true,
		UseSignedTimestamps: true,
	}
	args := []string{imgName}
	must(cmd.Exec(ctx, args), t)

	// Attest image
	predicate := `{ "buildType": "x", "builder": { "id": "2" }, "recipe": {} }`
	predicatePath := filepath.Join(t.TempDir(), "predicate.json")
	if err := os.WriteFile(predicatePath, []byte(predicate), 0o644); err != nil {
		t.Fatal(err)
	}
	attestCmd := attest.AttestCommand{
		KeyOpts:        ko,
		PredicatePath:  predicatePath,
		PredicateType:  "slsaprovenance",
		Timeout:        30 * time.Second,
		RekorEntryType: "dsse",
		TlogUpload:     true,
	}
	must(attestCmd.Exec(ctx, imgName), t)

	// Verify attestation
	verifyAttestation := cliverify.VerifyAttestationCommand{
		CertVerifyOptions: options.CertVerifyOptions{
			CertOidcIssuer: os.Getenv("OIDC_URL"),
			CertIdentity:   certID,
		},
		CommonVerifyOptions: options.CommonVerifyOptions{
			NewBundleFormat: true,
		},
		PredicateType:       "slsaprovenance",
		UseSignedTimestamps: true,
		CheckClaims:         true,
	}
	must(verifyAttestation.Exec(ctx, []string{imgName}), t)
}

func TestSignVerifyContainerWithSigningConfigWithCertificate(t *testing.T) {
	tufLocalCache := t.TempDir()
	t.Setenv("TUF_ROOT", tufLocalCache)
	viper.Set("timestamp-signer", "memory")
	viper.Set("timestamp-signer-hash", "sha256")
	tsaAPIServer := server.NewRestAPIServer("localhost", 0, []string{"http"}, false, 10*time.Second, 10*time.Second)
	tsaServer := httptest.NewServer(tsaAPIServer.GetHandler())
	t.Cleanup(tsaServer.Close)
	tufMirror := t.TempDir()
	tufServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.FileServer(http.Dir(tufMirror)).ServeHTTP(w, r)
	}))
	mirror := tufServer.URL

	cert, privKey, err := selfSignedCertificate()
	must(err, t)
	keysDir := t.TempDir()
	privKeyPath := filepath.Join(keysDir, "priv.key")
	privDer, err := x509.MarshalECPrivateKey(privKey)
	must(err, t)
	keyWriter, err := os.OpenFile(privKeyPath, os.O_WRONLY|os.O_CREATE, 0o600)
	must(err, t)
	defer keyWriter.Close()
	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privDer,
	}
	must(pem.Encode(keyWriter, block), t)

	certPath := filepath.Join(keysDir, "cert.pem")
	certWriter, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE, 0o600)
	must(err, t)
	defer certWriter.Close()
	block = &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	must(pem.Encode(certWriter, block), t)

	keys, err := cosign.ImportKeyPair(privKeyPath, passFunc)
	must(err, t)
	importKeyPath := filepath.Join(keysDir, "import-priv.key")
	must(os.WriteFile(importKeyPath, keys.PrivateBytes, 0o600), t)

	trustedRoot := prepareTrustedRootWithSelfSignedCertificate(t, certPath, tsaServer.URL)
	signingConfigStr := prepareSigningConfig(t, fulcioURL, rekorURL, "unused", tsaServer.URL+"/api/v1/timestamp")

	_, err = newTUF(tufMirror, []targetInfo{
		{
			name:   "trusted_root.json",
			source: trustedRoot,
		},
		{
			name:   "signing_config.v0.2.json",
			source: signingConfigStr,
		},
	})
	must(err, t)

	repo, stop := reg(t)
	defer stop()
	imgName := path.Join(repo, "cosign-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	ctx := context.Background()

	rootPath := filepath.Join(tufMirror, "1.root.json")
	must(initialize.DoInitialize(ctx, rootPath, mirror), t)

	ko := options.KeyOpts{
		NewBundleFormat:  true,
		SkipConfirmation: true,
		KeyRef:           importKeyPath,
		PassFunc:         passFunc,
	}
	trustedMaterial, err := cosign.TrustedRoot()
	must(err, t)
	ko.TrustedMaterial = trustedMaterial
	signingConfig, err := cosign.SigningConfig()
	must(err, t)
	ko.SigningConfig = signingConfig

	// Sign image with cert in bundle format
	so := options.SignOptions{
		Upload:          true,
		NewBundleFormat: true,
		Key:             importKeyPath,
		Cert:            certPath,
		TlogUpload:      false,
	}
	must(sign.SignCmd(ctx, ro, ko, so, []string{imgName}), t)

	// Verify image
	cmd := cliverify.VerifyCommand{
		CertVerifyOptions: options.CertVerifyOptions{
			CertOidcIssuerRegexp: ".*",
			CertIdentity:         "foo@bar.com",
		},
		NewBundleFormat: true,
		IgnoreSCT:       true,
	}
	args := []string{imgName}
	must(cmd.Exec(ctx, args), t)
}

func TestSignVerifyWithSigningConfigWithKey(t *testing.T) {
	tufLocalCache := t.TempDir()
	t.Setenv("TUF_ROOT", tufLocalCache)
	tufMirror := t.TempDir()
	viper.Set("timestamp-signer", "memory")
	viper.Set("timestamp-signer-hash", "sha256")
	tsaAPIServer := server.NewRestAPIServer("localhost", 0, []string{"http"}, false, 10*time.Second, 10*time.Second)
	tsaServer := httptest.NewServer(tsaAPIServer.GetHandler())
	t.Cleanup(tsaServer.Close)
	tufServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.FileServer(http.Dir(tufMirror)).ServeHTTP(w, r)
	}))
	mirror := tufServer.URL
	trustedRoot := prepareTrustedRoot(t, tsaServer.URL)
	signingConfigStr := prepareSigningConfig(t, fulcioURL, rekorURL, "unused", tsaServer.URL+"/api/v1/timestamp")

	_, err := newTUF(tufMirror, []targetInfo{
		{
			name:   "trusted_root.json",
			source: trustedRoot,
		},
		{
			name:   "signing_config.v0.2.json",
			source: signingConfigStr,
		},
	})
	must(err, t)

	ctx := context.Background()

	rootPath := filepath.Join(tufMirror, "1.root.json")
	must(initialize.DoInitialize(ctx, rootPath, mirror), t)

	_, privKeyPath, pubKeyPath := keypair(t, t.TempDir())

	ko := options.KeyOpts{
		PassFunc:         passFunc,
		SkipConfirmation: true,
	}
	trustedMaterial, err := cosign.TrustedRoot()
	must(err, t)
	ko.TrustedMaterial = trustedMaterial
	signingConfig, err := cosign.SigningConfig()
	must(err, t)
	ko.SigningConfig = signingConfig

	// Sign a blob using a provided key
	blob := "someblob"
	blobDir := t.TempDir()
	bp := filepath.Join(blobDir, blob)
	if err := os.WriteFile(bp, []byte(blob), 0o644); err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(blobDir, "bundle.json")
	ko.NewBundleFormat = true
	ko.BundlePath = bundlePath
	ko.KeyRef = privKeyPath

	_, err = sign.SignBlobCmd(ctx, ro, ko, bp, "", "", false, "", "", true)
	must(err, t)

	// Verify a blob with the key in the trusted root
	ko.KeyRef = pubKeyPath
	verifyBlobCmd := cliverify.VerifyBlobCmd{
		KeyOpts: ko,
	}
	err = verifyBlobCmd.Exec(ctx, bp)
	must(err, t)

	// Sign an attestation with a provided key
	statement := `{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"someblob","digest":{"alg":"7e9b6e7ba2842c91cf49f3e214d04a7a496f8214356f41d81a6e6dcad11f11e3"}}],"predicateType":"something","predicate":{}}`
	attestDir := t.TempDir()
	statementPath := filepath.Join(attestDir, "statement")
	if err := os.WriteFile(statementPath, []byte(statement), 0o644); err != nil {
		t.Fatal(err)
	}
	attBundlePath := filepath.Join(attestDir, "attest.bundle.json")
	ko.NewBundleFormat = true
	ko.BundlePath = attBundlePath
	ko.KeyRef = privKeyPath

	attestBlobCmd := attest.AttestBlobCommand{
		KeyOpts:        ko,
		RekorEntryType: "dsse",
		StatementPath:  statementPath,
		TlogUpload:     true,
	}
	must(attestBlobCmd.Exec(ctx, bp), t)

	// Verify an attestation with the key in the trusted root
	ko.KeyRef = pubKeyPath
	verifyBlobAttestationCmd := cliverify.VerifyBlobAttestationCommand{
		KeyOpts:     ko,
		Digest:      "7e9b6e7ba2842c91cf49f3e214d04a7a496f8214356f41d81a6e6dcad11f11e3",
		DigestAlg:   "alg",
		CheckClaims: true,
	}
	err = verifyBlobAttestationCmd.Exec(ctx, "")
	must(err, t)
}

func TestSignVerifyBundle(t *testing.T) {
	td := t.TempDir()
	repo, stop := reg(t)
	defer stop()

	imgName := path.Join(repo, "cosign-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, pubKeyPath := keypair(t, td)

	ctx := context.Background()

	// Sign image with key in bundle format
	ko := options.KeyOpts{
		KeyRef:           privKeyPath,
		PassFunc:         passFunc,
		RekorURL:         rekorURL,
		SkipConfirmation: true,
	}
	so := options.SignOptions{
		Upload:          true,
		NewBundleFormat: true,
		TlogUpload:      true,
	}
	must(sign.SignCmd(ctx, ro, ko, so, []string{imgName}), t)

	// Verify bundle
	trustedRootPath := prepareTrustedRoot(t, "")

	cmd := cliverify.VerifyCommand{
		CommonVerifyOptions: options.CommonVerifyOptions{
			TrustedRootPath: trustedRootPath,
		},
		KeyRef:              pubKeyPath,
		NewBundleFormat:     true,
		UseSignedTimestamps: false,
	}
	args := []string{imgName}
	must(cmd.Exec(ctx, args), t)

	// Sign image with key in bundle format without Rekor
	_, privKeyPath, pubKeyPath = keypair(t, td)
	ko = options.KeyOpts{
		KeyRef:           privKeyPath,
		PassFunc:         passFunc,
		SkipConfirmation: true,
	}
	so = options.SignOptions{
		Upload:          true,
		NewBundleFormat: true,
		TlogUpload:      false,
	}
	must(sign.SignCmd(ctx, ro, ko, so, []string{imgName}), t)
	// Verify bundle without Rekor
	cmd = cliverify.VerifyCommand{
		CommonVerifyOptions: options.CommonVerifyOptions{
			TrustedRootPath: trustedRootPath,
		},
		KeyRef:              pubKeyPath,
		NewBundleFormat:     true,
		IgnoreTlog:          true,
		UseSignedTimestamps: false,
	}
	must(cmd.Exec(ctx, args), t)

	// Sign image with Fulcio
	identityToken, err := getOIDCToken()
	if err != nil {
		t.Fatal(err)
	}

	ko = options.KeyOpts{
		IDToken:          identityToken,
		FulcioURL:        fulcioURL,
		RekorURL:         rekorURL,
		SkipConfirmation: true,
	}
	so = options.SignOptions{
		Upload:          true,
		NewBundleFormat: true,
		TlogUpload:      true,
	}
	must(sign.SignCmd(ctx, ro, ko, so, []string{imgName}), t)

	// Verify Fulcio-signed image
	cmd = cliverify.VerifyCommand{
		CertVerifyOptions: options.CertVerifyOptions{
			CertOidcIssuer:     os.Getenv("OIDC_URL"),
			CertIdentityRegexp: ".+",
		},
		CommonVerifyOptions: options.CommonVerifyOptions{
			TrustedRootPath: trustedRootPath,
		},
		NewBundleFormat:     true,
		UseSignedTimestamps: false,
	}
	must(cmd.Exec(ctx, args), t)

	// Add annotations and verify claims
	_, privKeyPath, pubKeyPath = keypair(t, td)
	ko = options.KeyOpts{
		KeyRef:           privKeyPath,
		PassFunc:         passFunc,
		RekorURL:         rekorURL,
		SkipConfirmation: true,
	}
	so = options.SignOptions{
		Upload:          true,
		NewBundleFormat: true,
		TlogUpload:      true,
		AnnotationOptions: options.AnnotationOptions{
			Annotations: []string{"foo=bar"},
		},
	}
	must(sign.SignCmd(ctx, ro, ko, so, []string{imgName}), t)
	cmd = cliverify.VerifyCommand{
		CommonVerifyOptions: options.CommonVerifyOptions{
			TrustedRootPath: trustedRootPath,
		},
		KeyRef:              pubKeyPath,
		NewBundleFormat:     true,
		UseSignedTimestamps: false,
		Annotations:         sigs.AnnotationsMap{Annotations: map[string]any{"foo": "bar"}},
		CheckClaims:         true,
	}
	must(cmd.Exec(ctx, args), t)

	// Verfying other annotations should not work
	cmd.Annotations.Annotations["baz"] = "bat"
	mustErr(cmd.Exec(ctx, args), t)
}

// TestSignVerifyBundleOffline tests that signing
// with a key and not verifying with Rekor or the TSA
// is entirely offline and doesn't try to request the TUF repo.
func TestSignVerifyBundleOffline(t *testing.T) {
	td := t.TempDir()
	repo, stop := reg(t)
	defer stop()

	imgName := path.Join(repo, "cosign-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	// To simulate offline verification, we'll set the TUF repo
	// env vars to invalid values. If signing were online, verification
	// would err out when trying to request the TUF repo contents.
	t.Setenv("TUF_ROOT", td)
	t.Setenv("TUF_MIRROR", td)

	_, privKeyPath, pubKeyPath := keypair(t, td)

	ctx := context.Background()

	// Sign image with key in bundle format
	ko := options.KeyOpts{
		KeyRef:           privKeyPath,
		PassFunc:         passFunc,
		SkipConfirmation: true,
	}
	so := options.SignOptions{
		Upload:          true,
		NewBundleFormat: true,
		TlogUpload:      false,
	}
	must(sign.SignCmd(ctx, ro, ko, so, []string{imgName}), t)

	// Verify bundle offline
	cmd := cliverify.VerifyCommand{
		KeyRef:              pubKeyPath,
		NewBundleFormat:     true,
		IgnoreTlog:          true,
		UseSignedTimestamps: false,
	}
	args := []string{imgName}
	must(cmd.Exec(ctx, args), t)
}

func TestTrustedRootCreateFromDefaults(t *testing.T) {
	tufLocalCache := t.TempDir()
	t.Setenv("TUF_ROOT", tufLocalCache)
	tufMirror := t.TempDir()
	tufServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.FileServer(http.Dir(tufMirror)).ServeHTTP(w, r)
	}))
	t.Cleanup(tufServer.Close)
	mirror := tufServer.URL
	viper.Set("timestamp-signer", "memory")
	viper.Set("timestamp-signer-hash", "sha256")
	tsaAPIServer := server.NewRestAPIServer("localhost", 0, []string{"http"}, false, 10*time.Second, 10*time.Second)
	tsaServer := httptest.NewServer(tsaAPIServer.GetHandler())
	t.Cleanup(tsaServer.Close)
	trustedRoot := prepareTrustedRoot(t, tsaServer.URL)

	_, err := newTUF(tufMirror, []targetInfo{
		{
			name:   "trusted_root.json",
			source: trustedRoot,
		},
	})
	must(err, t)

	ctx := context.Background()
	rootPath := filepath.Join(tufMirror, "1.root.json")
	must(initialize.DoInitialize(ctx, rootPath, mirror), t)

	// Create trusted root
	td := t.TempDir()
	outPath := filepath.Join(td, "trustedroot.json")
	trustedrootCreate := trustedroot.CreateCmd{
		WithDefaultServices: true,
		Out:                 outPath,
	}
	must(trustedrootCreate.Exec(context.Background()), t)

	// Verify trusted root was populated from TUF repo
	tr, err := root.NewTrustedRootFromPath(outPath)
	must(err, t)
	if len(tr.FulcioCertificateAuthorities()) != 1 {
		t.Fatal("expected default Fulcio certificate authority")
	}
	if len(tr.RekorLogs()) != 1 {
		t.Fatal("expected default Rekor log")
	}
	if len(tr.CTLogs()) != 1 {
		t.Fatal("expected default CT log")
	}
	if len(tr.TimestampingAuthorities()) != 1 {
		t.Fatal("expected default timestamp authority")
	}

	// Skip Fulcio
	trustedrootCreate.NoDefaultFulcio = true
	err = trustedrootCreate.Exec(ctx)
	must(err, t)
	tr, err = root.NewTrustedRootFromPath(outPath)
	must(err, t)
	if len(tr.FulcioCertificateAuthorities()) != 0 {
		t.Fatal("expected no Fulcio certificate authorities")
	}

	// Skip Rekor
	trustedrootCreate.NoDefaultRekor = true
	err = trustedrootCreate.Exec(ctx)
	must(err, t)
	tr, err = root.NewTrustedRootFromPath(outPath)
	must(err, t)
	if len(tr.RekorLogs()) != 0 {
		t.Fatal("expected no Rekor logs")
	}

	// Skip CT log
	trustedrootCreate.NoDefaultCTFE = true
	err = trustedrootCreate.Exec(ctx)
	must(err, t)
	tr, err = root.NewTrustedRootFromPath(outPath)
	must(err, t)
	if len(tr.CTLogs()) != 0 {
		t.Fatal("expected no CT logs")
	}

	// Skip TSA
	trustedrootCreate.NoDefaultTSA = true
	err = trustedrootCreate.Exec(ctx)
	must(err, t)
	tr, err = root.NewTrustedRootFromPath(outPath)
	must(err, t)
	if len(tr.TimestampingAuthorities()) != 0 {
		t.Fatal("expected no timestamp authorities")
	}
}

func TestSigningConfigCreateFromDefaults(t *testing.T) {
	tufLocalCache := t.TempDir()
	t.Setenv("TUF_ROOT", tufLocalCache)
	tufMirror := t.TempDir()
	tufServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.FileServer(http.Dir(tufMirror)).ServeHTTP(w, r)
	}))
	t.Cleanup(tufServer.Close)
	mirror := tufServer.URL
	tsaURL := "https://tsa.example"
	oidcURL := "https://oidc.example"
	signingConfigStr := prepareSigningConfig(t, fulcioURL, rekorURL, oidcURL, tsaURL+"/api/v1/timestamp")
	// Trusted root is needed as well for initialization
	viper.Set("timestamp-signer", "memory")
	viper.Set("timestamp-signer-hash", "sha256")
	tsaAPIServer := server.NewRestAPIServer("localhost", 0, []string{"http"}, false, 10*time.Second, 10*time.Second)
	tsaServer := httptest.NewServer(tsaAPIServer.GetHandler())
	t.Cleanup(tsaServer.Close)
	trustedRoot := prepareTrustedRoot(t, tsaServer.URL)

	_, err := newTUF(tufMirror, []targetInfo{
		{
			name:   "trusted_root.json",
			source: trustedRoot,
		},
		{
			name:   "signing_config.v0.2.json",
			source: signingConfigStr,
		},
	})
	must(err, t)

	ctx := context.Background()
	rootPath := filepath.Join(tufMirror, "1.root.json")
	must(initialize.DoInitialize(ctx, rootPath, mirror), t)

	// Create signing config
	td := t.TempDir()
	outPath := filepath.Join(td, "signingconfig.json")
	signingConfigCreate := signingconfig.CreateCmd{
		WithDefaultServices: true,
		Out:                 outPath,
	}
	must(signingConfigCreate.Exec(context.Background()), t)

	// Verify signing root was populated from TUF repo
	sc, err := root.NewSigningConfigFromPath(outPath)
	must(err, t)
	if len(sc.FulcioCertificateAuthorityURLs()) != 1 || sc.FulcioCertificateAuthorityURLs()[0].URL != fulcioURL {
		t.Fatal("expected default Fulcio certificate authority service")
	}
	if len(sc.RekorLogURLs()) != 1 || sc.RekorLogURLs()[0].URL != rekorURL {
		t.Fatal("expected default Rekor log service")
	}
	if len(sc.OIDCProviderURLs()) != 1 || sc.OIDCProviderURLs()[0].URL != oidcURL {
		t.Fatal("expected default OIDC provider service")
	}
	if len(sc.TimestampAuthorityURLs()) != 1 || sc.TimestampAuthorityURLs()[0].URL != tsaURL+"/api/v1/timestamp" {
		t.Fatal("expected default timestamp authority service")
	}

	// Skip Fulcio
	signingConfigCreate.NoDefaultFulcio = true
	err = signingConfigCreate.Exec(ctx)
	must(err, t)
	sc, err = root.NewSigningConfigFromPath(outPath)
	must(err, t)
	if len(sc.FulcioCertificateAuthorityURLs()) != 0 {
		t.Fatal("expected no Fulcio certificate authority services")
	}

	// Skip Rekor
	signingConfigCreate.NoDefaultRekor = true
	err = signingConfigCreate.Exec(ctx)
	must(err, t)
	sc, err = root.NewSigningConfigFromPath(outPath)
	must(err, t)
	if len(sc.RekorLogURLs()) != 0 {
		t.Fatal("expected no Rekor log services")
	}

	// Skip OIDC
	signingConfigCreate.NoDefaultOIDC = true
	err = signingConfigCreate.Exec(ctx)
	must(err, t)
	sc, err = root.NewSigningConfigFromPath(outPath)
	must(err, t)
	if len(sc.OIDCProviderURLs()) != 0 {
		t.Fatal("expected no OIDC provider services")
	}

	// Skip TSA
	signingConfigCreate.NoDefaultTSA = true
	err = signingConfigCreate.Exec(ctx)
	must(err, t)
	sc, err = root.NewSigningConfigFromPath(outPath)
	must(err, t)
	if len(sc.TimestampAuthorityURLs()) != 0 {
		t.Fatal("expected no timestamp authority services")
	}
}

func TestAttestVerify(t *testing.T) {
	for _, newBundleFormat := range []bool{false, true} {
		attestVerify(t,
			newBundleFormat,
			"slsaprovenance",
			`{ "buildType": "x", "builder": { "id": "2" }, "recipe": {} }`,
			`predicate: builder: id: "2"`,
			`predicate: builder: id: "1"`,
		)
	}
}

func TestAttestVerifySPDXJSON(t *testing.T) {
	attestationBytes, err := os.ReadFile("./testdata/bom-go-mod.spdx.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, newBundleFormat := range []bool{false, true} {
		attestVerify(t,
			newBundleFormat,
			"spdxjson",
			string(attestationBytes),
			`predicate: spdxVersion: "SPDX-2.2"`,
			`predicate: spdxVersion: "SPDX-9.9"`,
		)
	}
}

func TestAttestVerifyCycloneDXJSON(t *testing.T) {
	attestationBytes, err := os.ReadFile("./testdata/bom-go-mod.cyclonedx.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, newBundleFormat := range []bool{false, true} {
		attestVerify(t,
			newBundleFormat,
			"cyclonedx",
			string(attestationBytes),
			`predicate: specVersion: "1.4"`,
			`predicate: specVersion: "7.7"`,
		)
	}
}

func TestAttestVerifyURI(t *testing.T) {
	attestationBytes, err := os.ReadFile("./testdata/test-result.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, newBundleFormat := range []bool{false, true} {
		attestVerify(t,
			newBundleFormat,
			"https://example.com/TestResult/v1",
			string(attestationBytes),
			`predicate: passed: true`,
			`predicate: passed: false"`,
		)
	}
}

func attestVerify(t *testing.T, newBundleFormat bool, predicateType, attestation, goodCue, badCue string) {
	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	var imgName, attestationPath string
	if _, err := url.ParseRequestURI(predicateType); err == nil {
		// If the predicate type is URI, it cannot be included as image name and path.
		imgName = path.Join(repo, "cosign-attest-uri-e2e-image")
		attestationPath = filepath.Join(td, "cosign-attest-uri-e2e-attestation")
	} else {
		imgName = path.Join(repo, fmt.Sprintf("cosign-attest-%s-e2e-image", predicateType))
		attestationPath = filepath.Join(td, fmt.Sprintf("cosign-attest-%s-e2e-attestation", predicateType))
	}

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, pubKeyPath := keypair(t, td)

	ctx := context.Background()

	// Verify should fail at first
	verifyAttestation := cliverify.VerifyAttestationCommand{
		KeyRef:     pubKeyPath,
		IgnoreTlog: true,
		MaxWorkers: 10,
	}

	if newBundleFormat {
		verifyAttestation.NewBundleFormat = true
	}

	// Fail case when using without type and policy flag
	mustErr(verifyAttestation.Exec(ctx, []string{imgName}), t)

	if err := os.WriteFile(attestationPath, []byte(attestation), 0o600); err != nil {
		t.Fatal(err)
	}

	// Now attest the image
	ko := options.KeyOpts{KeyRef: privKeyPath, PassFunc: passFunc, NewBundleFormat: newBundleFormat}
	attestCmd := attest.AttestCommand{
		KeyOpts:        ko,
		PredicatePath:  attestationPath,
		PredicateType:  predicateType,
		Timeout:        30 * time.Second,
		RekorEntryType: "dsse",
	}
	must(attestCmd.Exec(ctx, imgName), t)

	// Use cue to verify attestation
	policyPath := filepath.Join(td, "policy.cue")
	verifyAttestation.PredicateType = predicateType
	verifyAttestation.Policies = []string{policyPath}

	// Fail case
	if err := os.WriteFile(policyPath, []byte(badCue), 0o600); err != nil {
		t.Fatal(err)
	}
	mustErr(verifyAttestation.Exec(ctx, []string{imgName}), t)

	// Success case
	if err := os.WriteFile(policyPath, []byte(goodCue), 0o600); err != nil {
		t.Fatal(err)
	}
	must(verifyAttestation.Exec(ctx, []string{imgName}), t)

	// Look for a specific annotation
	mustErr(verify(pubKeyPath, imgName, true, map[string]interface{}{"foo": "bar"}, "", false), t)
}

func TestAttestationDownload(t *testing.T) {
	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "cosign-attest-download-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, _ := keypair(t, td)
	ko := options.KeyOpts{KeyRef: privKeyPath, PassFunc: passFunc}

	ctx := context.Background()

	slsaAttestation := `{ "buildType": "x", "builder": { "id": "2" }, "recipe": {} }`
	slsaAttestationPath := filepath.Join(td, "attestation.slsa.json")
	if err := os.WriteFile(slsaAttestationPath, []byte(slsaAttestation), 0o600); err != nil {
		t.Fatal(err)
	}

	vulnAttestation := `
	{
    "invocation": {
      "parameters": null,
      "uri": "invocation.example.com/cosign-testing",
      "event_id": "",
      "builder.id": ""
    },
    "scanner": {
      "uri": "fakescanner.example.com/cosign-testing",
      "version": "",
      "db": {
        "uri": "",
        "version": ""
      },
      "result": null
    },
    "metadata": {
      "scanStartedOn": "2022-04-12T00:00:00Z",
      "scanFinishedOn": "2022-04-12T00:10:00Z"
    }
}
`
	vulnAttestationPath := filepath.Join(td, "attestation.vuln.json")
	if err := os.WriteFile(vulnAttestationPath, []byte(vulnAttestation), 0o600); err != nil {
		t.Fatal(err)
	}

	ref, err := name.ParseReference(imgName)
	if err != nil {
		t.Fatal(err)
	}
	regOpts := options.RegistryOptions{}
	ociremoteOpts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Attest to create a slsa attestation
	attestCommand := attest.AttestCommand{
		KeyOpts:        ko,
		PredicatePath:  slsaAttestationPath,
		PredicateType:  "slsaprovenance",
		Timeout:        30 * time.Second,
		Replace:        true,
		RekorEntryType: "dsse",
	}
	must(attestCommand.Exec(ctx, imgName), t)

	// Attest to create a vuln attestation
	attestCommand = attest.AttestCommand{
		KeyOpts:        ko,
		PredicatePath:  vulnAttestationPath,
		PredicateType:  "vuln",
		Timeout:        30 * time.Second,
		Replace:        true,
		RekorEntryType: "dsse",
	}
	must(attestCommand.Exec(ctx, imgName), t)

	// Call download.AttestationCmd() to ensure success
	attOpts := options.AttestationDownloadOptions{}
	must(download.AttestationCmd(ctx, regOpts, attOpts, imgName, os.Stdout), t)

	attestations, err := cosign.FetchAttestationsForReference(ctx, ref, attOpts.PredicateType, ociremoteOpts...)
	if err != nil {
		t.Fatal(err)
	}
	if len(attestations) != 2 {
		t.Fatal(fmt.Errorf("expected len(attestations) == 2, got %d", len(attestations)))
	}
}

func TestAttestationDownloadWithPredicateType(t *testing.T) {
	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "cosign-attest-download-predicate-type-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, _ := keypair(t, td)
	ko := options.KeyOpts{KeyRef: privKeyPath, PassFunc: passFunc}

	ctx := context.Background()

	slsaAttestation := `{ "buildType": "x", "builder": { "id": "2" }, "recipe": {} }`
	slsaAttestationPath := filepath.Join(td, "attestation.slsa.json")
	if err := os.WriteFile(slsaAttestationPath, []byte(slsaAttestation), 0o600); err != nil {
		t.Fatal(err)
	}

	vulnAttestation := `
	{
    "invocation": {
      "parameters": null,
      "uri": "invocation.example.com/cosign-testing",
      "event_id": "",
      "builder.id": ""
    },
    "scanner": {
      "uri": "fakescanner.example.com/cosign-testing",
      "version": "",
      "db": {
        "uri": "",
        "version": ""
      },
      "result": null
    },
    "metadata": {
      "scanStartedOn": "2022-04-12T00:00:00Z",
      "scanFinishedOn": "2022-04-12T00:10:00Z"
    }
}
`
	vulnAttestationPath := filepath.Join(td, "attestation.vuln.json")
	if err := os.WriteFile(vulnAttestationPath, []byte(vulnAttestation), 0o600); err != nil {
		t.Fatal(err)
	}

	ref, err := name.ParseReference(imgName)
	if err != nil {
		t.Fatal(err)
	}
	regOpts := options.RegistryOptions{}
	ociremoteOpts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Attest to create a slsa attestation
	attestCommand := attest.AttestCommand{
		KeyOpts:        ko,
		PredicatePath:  slsaAttestationPath,
		PredicateType:  "slsaprovenance",
		Timeout:        30 * time.Second,
		Replace:        true,
		RekorEntryType: "dsse",
	}
	must(attestCommand.Exec(ctx, imgName), t)

	// Attest to create a vuln attestation
	attestCommand = attest.AttestCommand{
		KeyOpts:        ko,
		PredicatePath:  vulnAttestationPath,
		PredicateType:  "vuln",
		Timeout:        30 * time.Second,
		Replace:        true,
		RekorEntryType: "dsse",
	}
	must(attestCommand.Exec(ctx, imgName), t)

	// Call download.AttestationCmd() to ensure success with --predicate-type
	attOpts := options.AttestationDownloadOptions{
		PredicateType: "vuln",
	}
	must(download.AttestationCmd(ctx, regOpts, attOpts, imgName, os.Stdout), t)

	predicateType, _ := options.ParsePredicateType(attOpts.PredicateType)
	attestations, err := cosign.FetchAttestationsForReference(ctx, ref, predicateType, ociremoteOpts...)
	if err != nil {
		t.Fatal(err)
	}
	if len(attestations) != 1 {
		t.Fatal(fmt.Errorf("expected len(attestations) == 1, got %d", len(attestations)))
	}
}

func TestAttestationDownloadWithBadPredicateType(t *testing.T) {
	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "cosign-attest-download-bad-type-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, _ := keypair(t, td)
	ko := options.KeyOpts{KeyRef: privKeyPath, PassFunc: passFunc}

	ctx := context.Background()

	slsaAttestation := `{ "buildType": "x", "builder": { "id": "2" }, "recipe": {} }`
	slsaAttestationPath := filepath.Join(td, "attestation.slsa.json")
	if err := os.WriteFile(slsaAttestationPath, []byte(slsaAttestation), 0o600); err != nil {
		t.Fatal(err)
	}

	regOpts := options.RegistryOptions{}

	// Attest to create a slsa attestation
	attestCommand := attest.AttestCommand{
		KeyOpts:        ko,
		PredicatePath:  slsaAttestationPath,
		PredicateType:  "slsaprovenance",
		Timeout:        30 * time.Second,
		Replace:        true,
		RekorEntryType: "dsse",
	}
	must(attestCommand.Exec(ctx, imgName), t)

	// Call download.AttestationCmd() to ensure failure with non-existent --predicate-type
	attOpts := options.AttestationDownloadOptions{
		PredicateType: "vuln",
	}
	mustErr(download.AttestationCmd(ctx, regOpts, attOpts, imgName, os.Stdout), t)
}

func TestAttestationReplaceCreate(t *testing.T) {
	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "cosign-attest-replace-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, _ := keypair(t, td)
	ko := options.KeyOpts{KeyRef: privKeyPath, PassFunc: passFunc}

	ctx := context.Background()

	slsaAttestation := `{ "buildType": "x", "builder": { "id": "2" }, "recipe": {} }`
	slsaAttestationPath := filepath.Join(td, "attestation.slsa.json")
	if err := os.WriteFile(slsaAttestationPath, []byte(slsaAttestation), 0o600); err != nil {
		t.Fatal(err)
	}

	ref, err := name.ParseReference(imgName)
	if err != nil {
		t.Fatal(err)
	}
	regOpts := options.RegistryOptions{}
	ociremoteOpts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Attest with replace=true to create an attestation
	attestCommand := attest.AttestCommand{
		KeyOpts:        ko,
		PredicatePath:  slsaAttestationPath,
		PredicateType:  "slsaprovenance",
		Timeout:        30 * time.Second,
		Replace:        true,
		RekorEntryType: "dsse",
	}
	must(attestCommand.Exec(ctx, imgName), t)

	// Download and count the attestations
	attOpts := options.AttestationDownloadOptions{}
	attestations, err := cosign.FetchAttestationsForReference(ctx, ref, attOpts.PredicateType, ociremoteOpts...)
	if err != nil {
		t.Fatal(err)
	}
	if len(attestations) != 1 {
		t.Fatal(fmt.Errorf("expected len(attestations) == 1, got %d", len(attestations)))
	}
}

func TestAttestationReplace(t *testing.T) {
	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "cosign-attest-replace-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, _ := keypair(t, td)
	ko := options.KeyOpts{KeyRef: privKeyPath, PassFunc: passFunc}

	ctx := context.Background()

	slsaAttestation := `{ "buildType": "x", "builder": { "id": "2" }, "recipe": {} }`
	slsaAttestationPath := filepath.Join(td, "attestation.slsa.json")
	if err := os.WriteFile(slsaAttestationPath, []byte(slsaAttestation), 0o600); err != nil {
		t.Fatal(err)
	}

	ref, err := name.ParseReference(imgName)
	if err != nil {
		t.Fatal(err)
	}
	regOpts := options.RegistryOptions{}
	ociremoteOpts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Attest once with replace=false creating an attestation
	attestCommand := attest.AttestCommand{
		KeyOpts:        ko,
		PredicatePath:  slsaAttestationPath,
		PredicateType:  "slsaprovenance",
		Timeout:        30 * time.Second,
		RekorEntryType: "dsse",
	}
	must(attestCommand.Exec(ctx, imgName), t)

	// Download and count the attestations
	attOpts := options.AttestationDownloadOptions{}
	attestations, err := cosign.FetchAttestationsForReference(ctx, ref, attOpts.PredicateType, ociremoteOpts...)
	if err != nil {
		t.Fatal(err)
	}
	if len(attestations) != 1 {
		t.Fatal(fmt.Errorf("expected len(attestations) == 1, got %d", len(attestations)))
	}

	// Attest again with replace=true, replacing the previous attestation
	attestCommand = attest.AttestCommand{
		KeyOpts:        ko,
		PredicatePath:  slsaAttestationPath,
		PredicateType:  "slsaprovenance",
		Replace:        true,
		Timeout:        30 * time.Second,
		RekorEntryType: "dsse",
	}
	must(attestCommand.Exec(ctx, imgName), t)
	attestations, err = cosign.FetchAttestationsForReference(ctx, ref, attOpts.PredicateType, ociremoteOpts...)
	// Download and count the attestations
	if err != nil {
		t.Fatal(err)
	}
	if len(attestations) != 1 {
		t.Fatal(fmt.Errorf("expected len(attestations) == 1, got %d", len(attestations)))
	}

	// Attest once more replace=true using a different predicate, to ensure it adds a new attestation
	attestCommand = attest.AttestCommand{
		KeyOpts:        ko,
		PredicatePath:  slsaAttestationPath,
		PredicateType:  "custom",
		Replace:        true,
		Timeout:        30 * time.Second,
		RekorEntryType: "dsse",
	}
	must(attestCommand.Exec(ctx, imgName), t)

	// Download and count the attestations
	attestations, err = cosign.FetchAttestationsForReference(ctx, ref, attOpts.PredicateType, ociremoteOpts...)
	if err != nil {
		t.Fatal(err)
	}
	if len(attestations) != 2 {
		t.Fatal(fmt.Errorf("expected len(attestations) == 2, got %d", len(attestations)))
	}
}

func TestAttestationRFC3161Timestamp(t *testing.T) {
	// TSA server needed to create timestamp
	viper.Set("timestamp-signer", "memory")
	viper.Set("timestamp-signer-hash", "sha256")
	apiServer := server.NewRestAPIServer("localhost", 0, []string{"http"}, false, 10*time.Second, 10*time.Second)
	server := httptest.NewServer(apiServer.GetHandler())
	t.Cleanup(server.Close)

	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "cosign-attest-timestamp-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, pubKeyPath := keypair(t, td)
	ko := options.KeyOpts{KeyRef: privKeyPath, PassFunc: passFunc}

	ctx := context.Background()

	slsaAttestation := `{ "buildType": "x", "builder": { "id": "2" }, "recipe": {} }`
	slsaAttestationPath := filepath.Join(td, "attestation.slsa.json")
	if err := os.WriteFile(slsaAttestationPath, []byte(slsaAttestation), 0o600); err != nil {
		t.Fatal(err)
	}

	ref, err := name.ParseReference(imgName)
	if err != nil {
		t.Fatal(err)
	}
	regOpts := options.RegistryOptions{}
	ociremoteOpts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Attest with TSA and skipping tlog creating an attestation
	attestCommand := attest.AttestCommand{
		KeyOpts:        ko,
		PredicatePath:  slsaAttestationPath,
		PredicateType:  "slsaprovenance",
		Timeout:        30 * time.Second,
		TSAServerURL:   server.URL + "/api/v1/timestamp",
		TlogUpload:     false,
		RekorEntryType: "dsse",
	}
	must(attestCommand.Exec(ctx, imgName), t)

	// Download and count the attestations
	attOpts := options.AttestationDownloadOptions{}
	attestations, err := cosign.FetchAttestationsForReference(ctx, ref, attOpts.PredicateType, ociremoteOpts...)
	if err != nil {
		t.Fatal(err)
	}
	if len(attestations) != 1 {
		t.Fatal(fmt.Errorf("expected len(attestations) == 1, got %d", len(attestations)))
	}

	client, err := tsaclient.GetTimestampClient(server.URL)
	if err != nil {
		t.Error(err)
	}

	chain, err := client.Timestamp.GetTimestampCertChain(nil)
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

	verifyAttestation := cliverify.VerifyAttestationCommand{
		KeyRef:           pubKeyPath,
		TSACertChainPath: file.Name(),
		IgnoreTlog:       true,
		PredicateType:    "slsaprovenance",
		MaxWorkers:       10,
	}

	must(verifyAttestation.Exec(ctx, []string{imgName}), t)

	// Ensure it verifies if you default to the new protobuf bundle format
	verifyAttestation.NewBundleFormat = true
	must(verifyAttestation.Exec(ctx, []string{imgName}), t)
}

func TestAttestationBlobRFC3161Timestamp(t *testing.T) {
	// TSA server needed to create timestamp
	viper.Set("timestamp-signer", "memory")
	viper.Set("timestamp-signer-hash", "sha256")
	apiServer := server.NewRestAPIServer("localhost", 0, []string{"http"}, false, 10*time.Second, 10*time.Second)
	server := httptest.NewServer(apiServer.GetHandler())
	t.Cleanup(server.Close)

	blob := "someblob"
	predicate := `{ "buildType": "x", "builder": { "id": "2" }, "recipe": {} }`
	predicateType := "slsaprovenance"

	td := t.TempDir()
	t.Cleanup(func() {
		os.RemoveAll(td)
	})

	bp := filepath.Join(td, blob)
	if err := os.WriteFile(bp, []byte(blob), 0o600); err != nil {
		t.Fatal(err)
	}

	predicatePath := filepath.Join(td, "predicate")
	if err := os.WriteFile(predicatePath, []byte(predicate), 0o600); err != nil {
		t.Fatal(err)
	}

	bundlePath := filepath.Join(td, "bundle.sigstore.json")
	_, privKeyPath, pubKeyPath := keypair(t, td)

	ctx := context.Background()
	ko := options.KeyOpts{
		KeyRef:          privKeyPath,
		BundlePath:      bundlePath,
		NewBundleFormat: true,
		TSAServerURL:    server.URL + "/api/v1/timestamp",
		PassFunc:        passFunc,
	}

	attestBlobCmd := attest.AttestBlobCommand{
		KeyOpts:        ko,
		PredicatePath:  predicatePath,
		PredicateType:  predicateType,
		Timeout:        30 * time.Second,
		TlogUpload:     false,
		RekorEntryType: "dsse",
	}
	must(attestBlobCmd.Exec(ctx, bp), t)

	client, err := tsaclient.GetTimestampClient(server.URL)
	if err != nil {
		t.Error(err)
	}

	chain, err := client.Timestamp.GetTimestampCertChain(nil)
	if err != nil {
		t.Fatalf("unexpected error getting timestamp chain: %v", err)
	}

	var certs []*x509.Certificate
	for block, contents := pem.Decode([]byte(chain.Payload)); ; block, contents = pem.Decode(contents) {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Error(err)
		}
		certs = append(certs, cert)

		if len(contents) == 0 {
			break
		}
	}

	tsaCA := &root.SigstoreTimestampingAuthority{
		Root:          certs[len(certs)-1],
		Intermediates: certs[:len(certs)-1],
	}

	trustedRoot, err := root.NewTrustedRoot(root.TrustedRootMediaType01, nil, nil, []root.TimestampingAuthority{tsaCA}, nil)
	if err != nil {
		t.Error(err)
	}

	trustedRootPath := filepath.Join(td, "trustedroot.json")
	trustedRootBytes, err := trustedRoot.MarshalJSON()
	if err != nil {
		t.Error(err)
	}
	if err := os.WriteFile(trustedRootPath, trustedRootBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	ko = options.KeyOpts{
		KeyRef:          pubKeyPath,
		BundlePath:      bundlePath,
		NewBundleFormat: true,
	}

	verifyBlobAttestation := cliverify.VerifyBlobAttestationCommand{
		KeyOpts:         ko,
		PredicateType:   predicateType,
		IgnoreTlog:      true,
		CheckClaims:     true,
		TrustedRootPath: trustedRootPath,
	}

	must(verifyBlobAttestation.Exec(ctx, bp), t)
}

func TestVerifyWithCARoots(t *testing.T) {
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

	imgName := path.Join(repo, "cosign-verify-caroots-e2e")
	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()
	blob := "someblob2sign"

	b := bytes.Buffer{}
	blobRef := filepath.Join(td, blob)
	if err := os.WriteFile(blobRef, []byte(blob), 0o644); err != nil {
		t.Fatal(err)
	}
	must(generate.GenerateCmd(context.Background(), options.RegistryOptions{}, imgName, nil, &b), t)

	rootCert, rootKey, _ := cert_test.GenerateRootCa()
	subCert, subKey, _ := cert_test.GenerateSubordinateCa(rootCert, rootKey)
	leafCert, privKey, _ := cert_test.GenerateLeafCert("subject@mail.com", "oidc-issuer", subCert, subKey)
	privKeyRef := importECDSAPrivateKey(t, privKey, td, "cosign-test-key.pem")
	pemRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Raw})
	pemSub := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: subCert.Raw})
	pemLeaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Raw})

	rootCert02, rootKey02, _ := cert_test.GenerateRootCa()
	subCert02, subKey02, _ := cert_test.GenerateSubordinateCa(rootCert02, rootKey02)
	leafCert02, _, _ := cert_test.GenerateLeafCert("subject02@mail.com", "oidc-issuer02", subCert02, subKey02)
	pemRoot02 := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert02.Raw})
	pemSub02 := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: subCert02.Raw})
	pemLeaf02 := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert02.Raw})
	pemsubRef02 := mkfile(string(pemSub02), td, t)
	pemrootRef02 := mkfile(string(pemRoot02), td, t)
	pemleafRef02 := mkfile(string(pemLeaf02), td, t)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	payloadref := mkfile(b.String(), td, t)

	h := sha256.Sum256(b.Bytes())
	signature, _ := privKey.Sign(rand.Reader, h[:], crypto.SHA256)
	b64signature := base64.StdEncoding.EncodeToString(signature)
	sigRef := mkfile(b64signature, td, t)
	pemsubRef := mkfile(string(pemSub), td, t)
	pemrootRef := mkfile(string(pemRoot), td, t)
	pemleafRef := mkfile(string(pemLeaf), td, t)
	certchainRef := mkfile(string(append(pemSub, pemRoot...)), td, t)

	pemrootBundleRef := mkfile(string(append(pemRoot, pemRoot02...)), td, t)
	pemsubBundleRef := mkfile(string(append(pemSub, pemSub02...)), td, t)

	tsclient, err := tsaclient.GetTimestampClient(server.URL)
	if err != nil {
		t.Error(err)
	}

	chain, err := tsclient.Timestamp.GetTimestampCertChain(nil)
	if err != nil {
		t.Fatalf("unexpected error getting timestamp chain: %v", err)
	}

	tsaChainRef, err := os.CreateTemp(os.TempDir(), "tempfile")
	if err != nil {
		t.Fatalf("error creating temp file: %v", err)
	}
	defer os.Remove(tsaChainRef.Name())
	_, err = tsaChainRef.WriteString(chain.Payload)
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

	// Now sign the blob with one key
	ko := options.KeyOpts{
		KeyRef:   privKeyRef,
		PassFunc: passFunc,
	}
	blobSig, err := sign.SignBlobCmd(ctx, ro, ko, blobRef, "", "", true, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	// the following fields with non-changing values are logically "factored out" for brevity
	// and passed to verifyKeylessTSAWithCARoots in the testing loop:
	// imageName string
	// tsaCertChainRef string
	// skipSCT   bool
	// skipTlogVerify bool
	tests := []struct {
		name      string
		rootRef   string
		subRef    string
		leafRef   string
		skipBlob  bool // skip the verify-blob test (for cases that need the image)
		wantError bool
	}{
		{
			"verify with root, intermediate and leaf certificates",
			pemrootRef,
			pemsubRef,
			pemleafRef,
			false,
			false,
		},
		// NB - "confusely" switching the root and intermediate PEM files does _NOT_ (currently) produce an error
		// - the Go crypto/x509 package doesn't strictly verify that the certificate chain is anchored
		// in a self-signed root certificate.  In this case, only the chain up to the intermediate
		// certificate is verified, and the root certificate is ignored.
		// See also https://gist.github.com/dmitris/15160f703b3038b1b00d03d3c7b66ce0 and in particular
		// https://gist.github.com/dmitris/15160f703b3038b1b00d03d3c7b66ce0#file-main-go-L133-L135 as an example.
		{
			"switch root and intermediate no error",
			pemsubRef,
			pemrootRef,
			pemleafRef,
			false,
			false,
		},
		{
			"leave out the root certificate",
			"",
			pemsubRef,
			pemleafRef,
			false,
			true,
		},
		{
			"leave out the intermediate certificate",
			pemrootRef,
			"",
			pemleafRef,
			false,
			true,
		},
		{
			"leave out the codesigning leaf certificate which is extracted from the image",
			pemrootRef,
			pemsubRef,
			"",
			true,
			false,
		},
		{
			"wrong leaf certificate",
			pemrootRef,
			pemsubRef,
			pemleafRef02,
			false,
			true,
		},
		{
			"root and intermediates bundles",
			pemrootBundleRef,
			pemsubBundleRef,
			pemleafRef,
			false,
			false,
		},
		{
			"wrong root and intermediates bundles",
			pemrootRef02,
			pemsubRef02,
			pemleafRef,
			false,
			true,
		},
		{
			"wrong root bundle",
			pemrootRef02,
			pemsubBundleRef,
			pemleafRef,
			false,
			true,
		},
		{
			"wrong intermediates bundle",
			pemrootRef,
			pemsubRef02,
			pemleafRef,
			false,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyKeylessTSAWithCARoots(imgName,
				tt.rootRef,
				tt.subRef,
				tt.leafRef,
				tsaChainRef.Name(),
				true,
				true)
			hasErr := (err != nil)
			if hasErr != tt.wantError {
				if tt.wantError {
					t.Errorf("%s - no expected error", tt.name)
				} else {
					t.Errorf("%s - unexpected error: %v", tt.name, err)
				}
			}
			if !tt.skipBlob {
				err = verifyBlobKeylessWithCARoots(blobRef,
					string(blobSig),
					tt.rootRef,
					tt.subRef,
					tt.leafRef,
					true,
					true)
				hasErr = (err != nil)
				if hasErr != tt.wantError {
					if tt.wantError {
						t.Errorf("%s - no expected error", tt.name)
					} else {
						t.Errorf("%s - unexpected error: %v", tt.name, err)
					}
				}
			}
		})
	}
}

func TestRekorBundle(t *testing.T) {
	td := t.TempDir()
	err := downloadAndSetEnv(t, rekorURL+"/api/v1/log/publicKey", env.VariableSigstoreRekorPublicKey.String(), td)
	if err != nil {
		t.Fatal(err)
	}

	repo, stop := reg(t)
	defer stop()

	imgName := path.Join(repo, "cosign-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, pubKeyPath := keypair(t, td)

	ko := options.KeyOpts{
		KeyRef:           privKeyPath,
		PassFunc:         passFunc,
		RekorURL:         rekorURL,
		SkipConfirmation: true,
	}
	so := options.SignOptions{
		Upload:     true,
		TlogUpload: true,
	}

	// Sign the image
	must(sign.SignCmd(t.Context(), ro, ko, so, []string{imgName}), t)
	// Make sure verify works
	must(verify(pubKeyPath, imgName, true, nil, "", false), t)

	// Make sure offline verification works with bundling
	must(verifyOffline(pubKeyPath, imgName, true, nil, ""), t)
}

func TestRekorOutput(t *testing.T) {
	td := t.TempDir()
	err := downloadAndSetEnv(t, rekorURL+"/api/v1/log/publicKey", env.VariableSigstoreRekorPublicKey.String(), td)
	if err != nil {
		t.Fatal(err)
	}

	repo, stop := reg(t)
	defer stop()

	imgName := path.Join(repo, "cosign-e2e")
	bundlePath := filepath.Join(td, "bundle.sig")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, pubKeyPath := keypair(t, td)

	ko := options.KeyOpts{
		KeyRef:     privKeyPath,
		PassFunc:   passFunc,
		RekorURL:   rekorURL,
		BundlePath: bundlePath,
	}
	so := options.SignOptions{
		Upload:     true,
		TlogUpload: true,
	}

	// Sign the image
	must(sign.SignCmd(t.Context(), ro, ko, so, []string{imgName}), t)
	// Make sure verify works
	must(verify(pubKeyPath, imgName, true, nil, "", false), t)

	if file, err := os.ReadFile(bundlePath); err != nil {
		t.Fatal(err)
	} else {
		var localCosignPayload cosign.LocalSignedPayload
		if err := json.Unmarshal(file, &localCosignPayload); err != nil {
			t.Fatal(err)
		}
	}
	// Make sure offline verification works with bundling
	must(verifyOffline(pubKeyPath, imgName, true, nil, ""), t)
}

func TestFulcioBundle(t *testing.T) {
	td := t.TempDir()
	err := downloadAndSetEnv(t, rekorURL+"/api/v1/log/publicKey", env.VariableSigstoreRekorPublicKey.String(), td)
	if err != nil {
		t.Fatal(err)
	}

	repo, stop := reg(t)
	defer stop()

	imgName := path.Join(repo, "cosign-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, pubKeyPath := keypair(t, td)

	ko := options.KeyOpts{
		KeyRef:           privKeyPath,
		PassFunc:         passFunc,
		RekorURL:         rekorURL,
		FulcioURL:        fulcioURL,
		SkipConfirmation: true,
	}
	so := options.SignOptions{
		Upload:           true,
		TlogUpload:       true,
		IssueCertificate: true,
	}

	// Sign the image
	must(sign.SignCmd(t.Context(), ro, ko, so, []string{imgName}), t)
	// Make sure verify works
	must(verify(pubKeyPath, imgName, true, nil, "", false), t)

	// Make sure offline verification works with bundling
	// use rekor prod since we have hardcoded the public key
	must(verifyOffline(pubKeyPath, imgName, true, nil, ""), t)
}

func TestRFC3161Timestamp(t *testing.T) {
	// TSA server needed to create timestamp
	viper.Set("timestamp-signer", "memory")
	viper.Set("timestamp-signer-hash", "sha256")
	apiServer := server.NewRestAPIServer("localhost", 0, []string{"http"}, false, 10*time.Second, 10*time.Second)
	server := httptest.NewServer(apiServer.GetHandler())
	t.Cleanup(server.Close)

	client, err := tsaclient.GetTimestampClient(server.URL)
	if err != nil {
		t.Error(err)
	}

	chain, err := client.Timestamp.GetTimestampCertChain(nil)
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

	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "cosign-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, pubKeyPath := keypair(t, td)

	ko := options.KeyOpts{
		KeyRef:       privKeyPath,
		PassFunc:     passFunc,
		TSAServerURL: server.URL + "/api/v1/timestamp",
	}
	so := options.SignOptions{
		Upload:     true,
		TlogUpload: false,
	}

	// Sign the image
	must(sign.SignCmd(t.Context(), ro, ko, so, []string{imgName}), t)
	// Make sure verify works against the TSA server
	must(verifyTSA(pubKeyPath, imgName, true, nil, "", file.Name(), true), t)
}

func TestRekorBundleAndRFC3161Timestamp(t *testing.T) {
	td := t.TempDir()
	err := downloadAndSetEnv(t, rekorURL+"/api/v1/log/publicKey", env.VariableSigstoreRekorPublicKey.String(), td)
	if err != nil {
		t.Fatal(err)
	}

	// TSA server needed to create timestamp
	viper.Set("timestamp-signer", "memory")
	viper.Set("timestamp-signer-hash", "sha256")
	apiServer := server.NewRestAPIServer("localhost", 0, []string{"http"}, false, 10*time.Second, 10*time.Second)
	server := httptest.NewServer(apiServer.GetHandler())
	t.Cleanup(server.Close)

	client, err := tsaclient.GetTimestampClient(server.URL)
	if err != nil {
		t.Error(err)
	}

	chain, err := client.Timestamp.GetTimestampCertChain(nil)
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

	repo, stop := reg(t)
	defer stop()

	imgName := path.Join(repo, "cosign-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, pubKeyPath := keypair(t, td)

	ko := options.KeyOpts{
		KeyRef:           privKeyPath,
		PassFunc:         passFunc,
		TSAServerURL:     server.URL + "/api/v1/timestamp",
		RekorURL:         rekorURL,
		SkipConfirmation: true,
	}
	so := options.SignOptions{
		Upload:     true,
		TlogUpload: true,
	}

	// Sign the image
	must(sign.SignCmd(t.Context(), ro, ko, so, []string{imgName}), t)
	// Make sure verify works against the Rekor and TSA clients
	must(verifyTSA(pubKeyPath, imgName, true, nil, "", file.Name(), false), t)
}

func TestDuplicateSign(t *testing.T) {
	td := t.TempDir()
	err := downloadAndSetEnv(t, rekorURL+"/api/v1/log/publicKey", env.VariableSigstoreRekorPublicKey.String(), td)
	if err != nil {
		t.Fatal(err)
	}

	repo, stop := reg(t)
	defer stop()

	imgName := path.Join(repo, "cosign-e2e")

	ref, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, pubKeyPath := keypair(t, td)

	ctx := context.Background()
	// Verify should fail at first
	mustErr(verify(pubKeyPath, imgName, true, nil, "", true), t)
	// So should download
	mustErr(download.SignatureCmd(ctx, options.RegistryOptions{}, imgName, os.Stdout), t)

	// Now sign the image
	ko := options.KeyOpts{
		KeyRef:   privKeyPath,
		PassFunc: passFunc,
	}
	so := options.SignOptions{
		Upload: true,
	}
	must(sign.SignCmd(ctx, ro, ko, so, []string{imgName}), t)

	// Now verify and download should work!
	// Ignore the tlog, because uploading to the tlog causes new signatures with new timestamp entries to be appended.
	must(verify(pubKeyPath, imgName, true, nil, "", true), t)
	must(download.SignatureCmd(ctx, options.RegistryOptions{}, imgName, os.Stdout), t)

	// Signing again should work just fine...
	must(sign.SignCmd(ctx, ro, ko, so, []string{imgName}), t)

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

	must(verify(keyRef, img, true, nil, "", false), t)
}

func TestGenerateKeyPairEnvVar(t *testing.T) {
	t.Setenv("COSIGN_PASSWORD", "foo")
	keys, err := cosign.GenerateKeyPair(generate.GetPass)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cosign.LoadPrivateKey(keys.PrivateBytes, []byte("foo"), nil); err != nil {
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
	t.Setenv("COSIGN_PASSWORD", password)
	ctx := context.Background()
	name := "cosign-secret"
	namespace := "default"
	if err := kubernetes.KeyPairSecret(ctx, fmt.Sprintf("k8s://%s/%s", namespace, name), generate.GetPass); err != nil {
		t.Fatal(err)
	}
	// make sure the secret actually exists

	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(), nil).ClientConfig()
	if err != nil {
		t.Fatal(err)
	}
	client, err := k8s.NewForConfig(cfg)
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
	// Clean up the secret (so tests can be re-run locally)
	err = client.CoreV1().Secrets(namespace).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		t.Fatal(err)
	}
}

func TestMultipleSignatures(t *testing.T) {
	td := t.TempDir()
	err := downloadAndSetEnv(t, rekorURL+"/api/v1/log/publicKey", env.VariableSigstoreRekorPublicKey.String(), td)
	if err != nil {
		t.Fatal(err)
	}

	repo, stop := reg(t)
	defer stop()

	td1 := t.TempDir()
	td2 := t.TempDir()

	imgName := path.Join(repo, "cosign-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, priv1, pub1 := keypair(t, td1)
	_, priv2, pub2 := keypair(t, td2)

	// Verify should fail at first for both keys
	mustErr(verify(pub1, imgName, true, nil, "", false), t)
	mustErr(verify(pub2, imgName, true, nil, "", false), t)

	// Now sign the image with one key
	ko := options.KeyOpts{
		KeyRef:           priv1,
		PassFunc:         passFunc,
		RekorURL:         rekorURL,
		SkipConfirmation: true,
	}
	so := options.SignOptions{
		Upload:     true,
		TlogUpload: true,
	}
	must(sign.SignCmd(t.Context(), ro, ko, so, []string{imgName}), t)
	// Now verify should work with that one, but not the other
	must(verify(pub1, imgName, true, nil, "", false), t)
	mustErr(verify(pub2, imgName, true, nil, "", false), t)

	// Now sign with the other key too
	ko.KeyRef = priv2
	must(sign.SignCmd(t.Context(), ro, ko, so, []string{imgName}), t)

	// Now verify should work with both
	must(verify(pub1, imgName, true, nil, "", false), t)
	must(verify(pub2, imgName, true, nil, "", false), t)
}

func TestSignBlob(t *testing.T) {
	td := t.TempDir()
	err := downloadAndSetEnv(t, rekorURL+"/api/v1/log/publicKey", env.VariableSigstoreRekorPublicKey.String(), td)
	if err != nil {
		t.Fatal(err)
	}
	blob := "someblob"
	td1 := t.TempDir()
	td2 := t.TempDir()
	bp := filepath.Join(td1, blob)

	if err := os.WriteFile(bp, []byte(blob), 0o644); err != nil {
		t.Fatal(err)
	}

	_, privKeyPath1, pubKeyPath1 := keypair(t, td1)
	_, _, pubKeyPath2 := keypair(t, td2)

	ctx := context.Background()

	ko1 := options.KeyOpts{
		KeyRef: pubKeyPath1,
	}
	ko2 := options.KeyOpts{
		KeyRef: pubKeyPath2,
	}
	// Verify should fail on a bad input
	cmd1 := cliverify.VerifyBlobCmd{
		KeyOpts:    ko1,
		SigRef:     "badsig",
		IgnoreTlog: true,
	}
	cmd2 := cliverify.VerifyBlobCmd{
		KeyOpts:    ko2,
		SigRef:     "badsig",
		IgnoreTlog: true,
	}
	mustErr(cmd1.Exec(ctx, blob), t)
	mustErr(cmd2.Exec(ctx, blob), t)

	// Now sign the blob with one key
	ko := options.KeyOpts{
		KeyRef:   privKeyPath1,
		PassFunc: passFunc,
	}
	sig, err := sign.SignBlobCmd(ctx, ro, ko, bp, "", "", true, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	// Now verify should work with that one, but not the other
	cmd1.SigRef = string(sig)
	cmd2.SigRef = string(sig)
	must(cmd1.Exec(ctx, bp), t)
	mustErr(cmd2.Exec(ctx, bp), t)
}

func TestSignBlobBundle(t *testing.T) {
	blob := "someblob"
	td1 := t.TempDir()
	bp := filepath.Join(td1, blob)
	bundlePath := filepath.Join(td1, "bundle.sig")

	if err := os.WriteFile(bp, []byte(blob), 0o644); err != nil {
		t.Fatal(err)
	}

	err := downloadAndSetEnv(t, rekorURL+"/api/v1/log/publicKey", env.VariableSigstoreRekorPublicKey.String(), td1)
	if err != nil {
		t.Fatal(err)
	}

	_, privKeyPath1, pubKeyPath1 := keypair(t, td1)

	ctx := context.Background()

	ko1 := options.KeyOpts{
		KeyRef:     pubKeyPath1,
		BundlePath: bundlePath,
	}
	// Verify should fail on a bad input
	verifyBlobCmd := cliverify.VerifyBlobCmd{
		KeyOpts:    ko1,
		IgnoreTlog: true,
	}
	mustErr(verifyBlobCmd.Exec(ctx, bp), t)

	// Now sign the blob with one key
	ko := options.KeyOpts{
		KeyRef:           privKeyPath1,
		PassFunc:         passFunc,
		BundlePath:       bundlePath,
		RekorURL:         rekorURL,
		SkipConfirmation: true,
	}
	if _, err := sign.SignBlobCmd(ctx, ro, ko, bp, "", "", true, "", "", false); err != nil {
		t.Fatal(err)
	}
	// Now verify should work
	must(verifyBlobCmd.Exec(ctx, bp), t)

	// Now we turn on the tlog and sign again
	if _, err := sign.SignBlobCmd(ctx, ro, ko, bp, "", "", true, "", "", true); err != nil {
		t.Fatal(err)
	}

	// Point to a fake rekor server to make sure offline verification of the tlog entry works
	verifyBlobCmd.RekorURL = "notreal"
	verifyBlobCmd.IgnoreTlog = false
	must(verifyBlobCmd.Exec(ctx, bp), t)
}

func TestSignBlobNewBundle(t *testing.T) {
	td1 := t.TempDir()

	blob := "someblob"
	blobPath := filepath.Join(td1, blob)
	if err := os.WriteFile(blobPath, []byte(blob), 0o644); err != nil {
		t.Fatal(err)
	}

	bundlePath := filepath.Join(td1, "bundle.sigstore.json")

	ctx := context.Background()
	_, privKeyPath, pubKeyPath := keypair(t, td1)

	ko1 := options.KeyOpts{
		KeyRef:          pubKeyPath,
		BundlePath:      bundlePath,
		NewBundleFormat: true,
	}

	verifyBlobCmd := cliverify.VerifyBlobCmd{
		KeyOpts:    ko1,
		IgnoreTlog: true,
	}

	// Verify should fail before bundle is written
	mustErr(verifyBlobCmd.Exec(ctx, blobPath), t)

	// Produce signed bundle
	ko := options.KeyOpts{
		KeyRef:          privKeyPath,
		PassFunc:        passFunc,
		BundlePath:      bundlePath,
		NewBundleFormat: true,
	}

	if _, err := sign.SignBlobCmd(ctx, ro, ko, blobPath, "", "", true, "", "", false); err != nil {
		t.Fatal(err)
	}

	// Verify should succeed now that bundle is written
	must(verifyBlobCmd.Exec(ctx, blobPath), t)
}

func TestSignBlobNewBundleNonSHA256(t *testing.T) {
	td1 := t.TempDir()

	blob := "someblob"
	blobPath := filepath.Join(td1, blob)
	if err := os.WriteFile(blobPath, []byte(blob), 0o644); err != nil {
		t.Fatal(err)
	}

	bundlePath := filepath.Join(td1, "bundle.sigstore.json")

	ctx := context.Background()

	// Generate ecdsa-p521 key
	_, privKeyPath, pubKeyPath := keypairWithAlgorithm(t, td1, v1.PublicKeyDetails_PKIX_ECDSA_P521_SHA_512)

	ko := options.KeyOpts{
		KeyRef:          privKeyPath,
		PassFunc:        passFunc,
		BundlePath:      bundlePath,
		NewBundleFormat: true,
	}
	if _, err := sign.SignBlobCmd(ctx, ro, ko, blobPath, "", "", true, "", "", false); err != nil {
		t.Fatal(err)
	}

	ko1 := options.KeyOpts{
		KeyRef:          pubKeyPath,
		BundlePath:      bundlePath,
		NewBundleFormat: true,
	}
	verifyBlobCmd := cliverify.VerifyBlobCmd{
		KeyOpts:       ko1,
		IgnoreTlog:    true,
		HashAlgorithm: crypto.SHA512,
	}
	must(verifyBlobCmd.Exec(ctx, blobPath), t)
}

func TestSignBlobNewBundleNonDefaultAlgorithm(t *testing.T) {
	tts := []struct {
		algo v1.PublicKeyDetails
	}{
		{v1.PublicKeyDetails_PKIX_ECDSA_P384_SHA_384},
		{v1.PublicKeyDetails_PKIX_ECDSA_P521_SHA_512},
		{v1.PublicKeyDetails_PKIX_RSA_PKCS1V15_2048_SHA256},
		{v1.PublicKeyDetails_PKIX_RSA_PKCS1V15_3072_SHA256},
		{v1.PublicKeyDetails_PKIX_RSA_PKCS1V15_4096_SHA256},
		// ed25519 and ed25519ph aren't supported for the default flow.
		// By default, we sign using the prehash variant for a ed25519 key.
		// Rekor supports ed25519ph for a hashedrekord, but Fulcio doesn't.
	}

	td := t.TempDir()

	// set up SIGSTORE_ variables to point to keys for the local instances
	err := setLocalEnv(t, td)
	if err != nil {
		t.Fatal(err)
	}

	err = fulcioroots.ReInit()
	if err != nil {
		t.Fatal(err)
	}

	identityToken, err := getOIDCToken()
	if err != nil {
		t.Fatal(err)
	}

	// Use the CreateCmd approach to create a trusted root
	rootFile := os.Getenv("SIGSTORE_ROOT_FILE")
	ctfePubKey := os.Getenv("SIGSTORE_CT_LOG_PUBLIC_KEY_FILE")
	rekorPubKey := os.Getenv("SIGSTORE_REKOR_PUBLIC_KEY")
	// Create a temporary file for the trusted root JSON
	trustedRootPath := filepath.Join(td, "trustedroot.json")

	// Create a CreateCmd instance
	createCmd := trustedroot.CreateCmd{
		CertChain:    []string{rootFile},
		Out:          trustedRootPath,
		RekorKeyPath: []string{rekorPubKey},
		CtfeKeyPath:  []string{ctfePubKey},
	}

	// Execute the command to create the trusted root
	if err := createCmd.Exec(context.Background()); err != nil {
		t.Fatal(err)
	}

	for _, tt := range tts {
		t.Run(tt.algo.String(), func(t *testing.T) {
			td1 := t.TempDir()

			blob := "someblob"
			blobPath := filepath.Join(td1, blob)
			if err := os.WriteFile(blobPath, []byte(blob), 0o644); err != nil {
				t.Fatal(err)
			}

			bundlePath := filepath.Join(td1, "bundle.sigstore.json")

			ctx := context.Background()
			_, privKeyPath, _ := keypairWithAlgorithm(t, td1, tt.algo)

			verifyBlobCmd := cliverify.VerifyBlobCmd{
				TrustedRootPath: trustedRootPath,
				KeyOpts: options.KeyOpts{
					FulcioURL:        fulcioURL,
					RekorURL:         rekorURL,
					PassFunc:         passFunc,
					BundlePath:       bundlePath,
					NewBundleFormat:  true,
					SkipConfirmation: true,
				},
				CertVerifyOptions: options.CertVerifyOptions{
					CertOidcIssuerRegexp: ".*",
					CertIdentityRegexp:   ".*",
				},
			}

			// Verify should fail before bundle is written
			mustErr(verifyBlobCmd.Exec(ctx, blobPath), t)

			// Produce signed bundle
			ko := options.KeyOpts{
				FulcioURL:                      fulcioURL,
				RekorURL:                       rekorURL,
				IDToken:                        identityToken,
				KeyRef:                         privKeyPath,
				PassFunc:                       passFunc,
				BundlePath:                     bundlePath,
				NewBundleFormat:                true,
				IssueCertificateForExistingKey: true,
				SkipConfirmation:               true,
			}

			if _, err := sign.SignBlobCmd(ctx, ro, ko, blobPath, "", "", true, "", "", true); err != nil {
				t.Fatal(err)
			}

			// Copy bundle to /tmp with test name
			bundleBytes, err := os.ReadFile(bundlePath)
			if err != nil {
				t.Fatal(err)
			}
			tmpBundlePath := filepath.Join("/tmp", fmt.Sprintf("bundle-%s", tt.algo))
			if err := os.WriteFile(tmpBundlePath, bundleBytes, 0o644); err != nil {
				t.Fatal(err)
			}

			// Verify should succeed now that bundle is written
			must(verifyBlobCmd.Exec(ctx, blobPath), t)
		})
	}
}

func TestSignBlobRFC3161TimestampBundle(t *testing.T) {
	td := t.TempDir()
	err := downloadAndSetEnv(t, rekorURL+"/api/v1/log/publicKey", env.VariableSigstoreRekorPublicKey.String(), td)
	if err != nil {
		t.Fatal(err)
	}
	// TSA server needed to create timestamp
	viper.Set("timestamp-signer", "memory")
	viper.Set("timestamp-signer-hash", "sha256")
	apiServer := server.NewRestAPIServer("localhost", 0, []string{"http"}, false, 10*time.Second, 10*time.Second)
	server := httptest.NewServer(apiServer.GetHandler())
	t.Cleanup(server.Close)

	blob := "someblob"
	bp := filepath.Join(td, blob)
	bundlePath := filepath.Join(td, "bundle.sig")
	tsPath := filepath.Join(td, "rfc3161Timestamp.json")

	if err := os.WriteFile(bp, []byte(blob), 0o644); err != nil {
		t.Fatal(err)
	}

	client, err := tsaclient.GetTimestampClient(server.URL)
	if err != nil {
		t.Error(err)
	}

	chain, err := client.Timestamp.GetTimestampCertChain(nil)
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

	_, privKeyPath1, pubKeyPath1 := keypair(t, td)

	ctx := context.Background()

	ko1 := options.KeyOpts{
		KeyRef:               pubKeyPath1,
		BundlePath:           bundlePath,
		RFC3161TimestampPath: tsPath,
		TSACertChainPath:     file.Name(),
	}
	// Verify should fail on a bad input
	verifyBlobCmd := cliverify.VerifyBlobCmd{
		KeyOpts:    ko1,
		IgnoreTlog: true,
	}
	mustErr(verifyBlobCmd.Exec(ctx, bp), t)

	// Now sign the blob with one key
	ko := options.KeyOpts{
		KeyRef:               privKeyPath1,
		PassFunc:             passFunc,
		BundlePath:           bundlePath,
		RFC3161TimestampPath: tsPath,
		TSAServerURL:         server.URL + "/api/v1/timestamp",
		RekorURL:             rekorURL,
		SkipConfirmation:     true,
	}
	if _, err := sign.SignBlobCmd(ctx, ro, ko, bp, "", "", true, "", "", false); err != nil {
		t.Fatal(err)
	}
	// Now verify should work
	must(verifyBlobCmd.Exec(ctx, bp), t)

	// Now we turn on the tlog and sign again
	if _, err := sign.SignBlobCmd(ctx, ro, ko, bp, "", "", true, "", "", true); err != nil {
		t.Fatal(err)
	}
	// Point to a fake rekor server to make sure offline verification of the tlog entry works
	verifyBlobCmd.RekorURL = "notreal"
	verifyBlobCmd.IgnoreTlog = false
	must(verifyBlobCmd.Exec(ctx, bp), t)
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

func TestSaveLoad(t *testing.T) {
	td := t.TempDir()
	err := downloadAndSetEnv(t, rekorURL+"/api/v1/log/publicKey", env.VariableSigstoreRekorPublicKey.String(), td)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		description     string
		getSignedEntity func(t *testing.T, n string) (name.Reference, *remote.Descriptor, func())
		newBundle       bool
	}{
		{
			description:     "save and load an image",
			getSignedEntity: mkimage,
			newBundle:       false,
		},
		{
			description:     "save and load an image bundle",
			getSignedEntity: mkimage,
			newBundle:       true,
		},
		{
			description:     "save and load an image index",
			getSignedEntity: mkimageindex,
			newBundle:       false,
		},
	}
	for i, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			repo, stop := reg(t)
			defer stop()
			keysDir := t.TempDir()

			imgName := path.Join(repo, fmt.Sprintf("save-load-%d", i))

			_, _, cleanup := test.getSignedEntity(t, imgName)
			defer cleanup()

			_, privKeyPath, pubKeyPath := keypair(t, keysDir)

			ctx := context.Background()
			// Now sign the image and verify it
			ko := options.KeyOpts{
				KeyRef:           privKeyPath,
				PassFunc:         passFunc,
				RekorURL:         rekorURL,
				SkipConfirmation: true,
			}
			so := options.SignOptions{
				Upload:          true,
				TlogUpload:      true,
				NewBundleFormat: test.newBundle,
			}
			must(sign.SignCmd(ctx, ro, ko, so, []string{imgName}), t)
			trustedRootPath := prepareTrustedRoot(t, "")
			bundleVerifyCmd := cliverify.VerifyCommand{
				CommonVerifyOptions: options.CommonVerifyOptions{
					TrustedRootPath: trustedRootPath,
				},
				KeyRef:              pubKeyPath,
				NewBundleFormat:     true,
				UseSignedTimestamps: false,
			}

			if test.newBundle {
				must(bundleVerifyCmd.Exec(ctx, []string{imgName}), t)
			} else {
				must(verify(pubKeyPath, imgName, true, nil, "", false), t)
			}

			// save the image to a temp dir
			imageDir := t.TempDir()
			must(cli.SaveCmd(ctx, options.SaveOptions{Directory: imageDir}, imgName), t)

			// verify the local image using a local key
			// if we are not using protobuf bundle format
			if !test.newBundle {
				must(verifyLocal(pubKeyPath, imageDir, true, nil, ""), t)
			}

			// load the image from the temp dir into a new image and verify the new image
			imgName2 := path.Join(repo, fmt.Sprintf("save-load-%d-2", i))
			must(cli.LoadCmd(ctx, options.LoadOptions{Directory: imageDir}, imgName2), t)
			if test.newBundle {
				must(bundleVerifyCmd.Exec(ctx, []string{imgName2}), t)
			} else {
				must(verify(pubKeyPath, imgName2, true, nil, "", false), t)
			}
		})
	}
}

// TestSaveLoadAutoDetectFormat verifies that local image verification auto-detects
// the signature format (v2 attached signatures vs v3 bundles) without requiring
// explicit --new-bundle-format flag. This tests the fix for sigstore/cosign#4621.
func TestSaveLoadAutoDetectFormat(t *testing.T) {
	td := t.TempDir()
	err := downloadAndSetEnv(t, rekorURL+"/api/v1/log/publicKey", env.VariableSigstoreRekorPublicKey.String(), td)
	if err != nil {
		t.Fatal(err)
	}

	// Test v2 attached signatures - this is the main use case for #4621
	// where users have v2 signatures but cosign v3 defaults to --new-bundle-format=true
	t.Run("auto-detect v2 attached signatures", func(t *testing.T) {
		repo, stop := reg(t)
		defer stop()
		keysDir := t.TempDir()

		imgName := path.Join(repo, "auto-detect-v2")

		_, _, cleanup := mkimage(t, imgName)
		defer cleanup()

		_, privKeyPath, pubKeyPath := keypair(t, keysDir)

		ctx := context.Background()
		// Sign the image with v2 format (no bundle)
		ko := options.KeyOpts{
			KeyRef:           privKeyPath,
			PassFunc:         passFunc,
			RekorURL:         rekorURL,
			SkipConfirmation: true,
		}
		so := options.SignOptions{
			Upload:          true,
			TlogUpload:      true,
			NewBundleFormat: false, // v2 format
		}
		must(sign.SignCmd(ctx, ro, ko, so, []string{imgName}), t)

		// Save the image to a temp dir
		imageDir := t.TempDir()
		must(cli.SaveCmd(ctx, options.SaveOptions{Directory: imageDir}, imgName), t)

		// Verify the local image WITHOUT specifying --new-bundle-format
		// The format should be auto-detected as v2, allowing verification to succeed
		verifyCmd := cliverify.VerifyCommand{
			KeyRef:     pubKeyPath,
			LocalImage: true,
			MaxWorkers: 10,
			// Explicitly NOT setting NewBundleFormat - should auto-detect as v2
		}
		must(verifyCmd.Exec(ctx, []string{imageDir}), t)
	})

	// For v3 bundles, local verification is not currently supported.
	// The existing TestSaveLoad shows that v3 bundles must be loaded back
	// to a registry for verification. This test verifies the auto-detection
	// correctly identifies v3 bundles.
	t.Run("auto-detect v3 bundle format and load", func(t *testing.T) {
		repo, stop := reg(t)
		defer stop()
		keysDir := t.TempDir()

		imgName := path.Join(repo, "auto-detect-v3")

		_, _, cleanup := mkimage(t, imgName)
		defer cleanup()

		_, privKeyPath, pubKeyPath := keypair(t, keysDir)

		ctx := context.Background()
		// Sign the image with v3 format (bundle)
		ko := options.KeyOpts{
			KeyRef:           privKeyPath,
			PassFunc:         passFunc,
			RekorURL:         rekorURL,
			SkipConfirmation: true,
		}
		so := options.SignOptions{
			Upload:          true,
			TlogUpload:      true,
			NewBundleFormat: true, // v3 format
		}
		must(sign.SignCmd(ctx, ro, ko, so, []string{imgName}), t)

		// Save the image to a temp dir
		imageDir := t.TempDir()
		must(cli.SaveCmd(ctx, options.SaveOptions{Directory: imageDir}, imgName), t)

		// Load the image back to a registry and verify from there
		// (local verification of v3 bundles is not currently supported)
		imgName2 := path.Join(repo, "auto-detect-v3-loaded")
		must(cli.LoadCmd(ctx, options.LoadOptions{Directory: imageDir}, imgName2), t)

		trustedRootPath := prepareTrustedRoot(t, "")
		verifyCmd := cliverify.VerifyCommand{
			CommonVerifyOptions: options.CommonVerifyOptions{
				TrustedRootPath: trustedRootPath,
			},
			KeyRef:              pubKeyPath,
			NewBundleFormat:     true,
			UseSignedTimestamps: false,
		}
		must(verifyCmd.Exec(ctx, []string{imgName2}), t)
	})
}

func TestSaveLoadAttestation(t *testing.T) {
	td := t.TempDir()
	err := downloadAndSetEnv(t, rekorURL+"/api/v1/log/publicKey", env.VariableSigstoreRekorPublicKey.String(), td)
	if err != nil {
		t.Fatal(err)
	}

	repo, stop := reg(t)
	defer stop()

	imgName := path.Join(repo, "save-load")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, pubKeyPath := keypair(t, td)

	ctx := context.Background()
	// Now sign the image and verify it
	ko := options.KeyOpts{
		KeyRef:           privKeyPath,
		PassFunc:         passFunc,
		RekorURL:         rekorURL,
		SkipConfirmation: true,
	}
	so := options.SignOptions{
		Upload:     true,
		TlogUpload: true,
	}
	must(sign.SignCmd(ctx, ro, ko, so, []string{imgName}), t)
	must(verify(pubKeyPath, imgName, true, nil, "", false), t)

	// now, append an attestation to the image
	slsaAttestation := `{ "buildType": "x", "builder": { "id": "2" }, "recipe": {} }`
	slsaAttestationPath := filepath.Join(td, "attestation.slsa.json")
	if err := os.WriteFile(slsaAttestationPath, []byte(slsaAttestation), 0o600); err != nil {
		t.Fatal(err)
	}

	// Now attest the image
	ko = options.KeyOpts{KeyRef: privKeyPath, PassFunc: passFunc}
	attestCommand := attest.AttestCommand{
		KeyOpts:        ko,
		PredicatePath:  slsaAttestationPath,
		PredicateType:  "slsaprovenance",
		Timeout:        30 * time.Second,
		RekorEntryType: "dsse",
	}
	must(attestCommand.Exec(ctx, imgName), t)

	// save the image to a temp dir
	imageDir := t.TempDir()
	must(cli.SaveCmd(ctx, options.SaveOptions{Directory: imageDir}, imgName), t)

	// load the image from the temp dir into a new image and verify the new image
	imgName2 := path.Join(repo, "save-load-2")
	must(cli.LoadCmd(ctx, options.LoadOptions{Directory: imageDir}, imgName2), t)
	must(verify(pubKeyPath, imgName2, true, nil, "", false), t)
	// Use cue to verify attestation on the new image
	policyPath := filepath.Join(td, "policy.cue")
	verifyAttestation := cliverify.VerifyAttestationCommand{
		KeyRef:     pubKeyPath,
		IgnoreTlog: true,
		MaxWorkers: 10,
	}
	verifyAttestation.PredicateType = "slsaprovenance"
	verifyAttestation.Policies = []string{policyPath}
	// Success case (remote)
	cuePolicy := `predicate: builder: id: "2"`
	if err := os.WriteFile(policyPath, []byte(cuePolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	must(verifyAttestation.Exec(ctx, []string{imgName2}), t)
	// Success case (local)
	verifyAttestation.LocalImage = true
	must(verifyAttestation.Exec(ctx, []string{imageDir}), t)
}

func TestAttestDownloadAttachNewBundle(t *testing.T) {
	repo, stop := reg(t)
	defer stop()

	imgName := path.Join(repo, "attest-new-bundle")
	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	// Download should fail before attesting
	ctx := context.Background()
	regOpts := options.RegistryOptions{}
	attOpts := options.AttestationDownloadOptions{}
	mustErr(download.AttestationCmd(ctx, regOpts, attOpts, imgName, os.Stdout), t)

	// Attest first image
	td := t.TempDir()
	_, privKeyPath, _ := keypair(t, td)
	ko := options.KeyOpts{KeyRef: privKeyPath, PassFunc: passFunc, NewBundleFormat: true}

	slsaAttestation := `{ "buildType": "x", "builder": { "id": "2" }, "recipe": {} }`
	slsaAttestationPath := filepath.Join(td, "attestation.slsa.json")
	if err := os.WriteFile(slsaAttestationPath, []byte(slsaAttestation), 0o600); err != nil {
		t.Fatal(err)
	}

	attestCommand := attest.AttestCommand{
		KeyOpts:        ko,
		PredicatePath:  slsaAttestationPath,
		PredicateType:  "slsaprovenance",
		RekorEntryType: "dsse",
	}

	must(attestCommand.Exec(ctx, imgName), t)

	// Download should now succeed - redirect stdout to use with attach
	out := bytes.Buffer{}
	must(download.AttestationCmd(ctx, regOpts, attOpts, imgName, &out), t)

	// Create a new image to attach to
	img2Name := path.Join(repo, "attest-new-bundle-2")
	_, _, cleanup = mkimage(t, img2Name)
	defer cleanup()

	bundlePath := filepath.Join(td, "downloaded-bundle.sigstore.json")
	if err := os.WriteFile(bundlePath, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	must(attach.AttestationCmd(ctx, regOpts, []string{bundlePath}, img2Name), t)

	// Download should succeed on second image
	must(download.AttestationCmd(ctx, regOpts, attOpts, img2Name, os.Stdout), t)
}

func TestSignDownloadAttachNewBundle(t *testing.T) {
	repo, stop := reg(t)
	defer stop()

	imgName := path.Join(repo, "sign-new-bundle")
	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	// Download should fail before attesting
	ctx := context.Background()
	regOpts := options.RegistryOptions{}
	mustErr(download.SignatureCmd(ctx, regOpts, imgName, os.Stdout), t)

	// Sign first image
	td := t.TempDir()
	_, privKeyPath, _ := keypair(t, td)
	ko := options.KeyOpts{KeyRef: privKeyPath, PassFunc: passFunc}
	so := options.SignOptions{
		NewBundleFormat: true,
		Upload:          true,
	}

	must(sign.SignCmd(ctx, ro, ko, so, []string{imgName}), t)

	// Download should now succeed - redirect stdout to use with attach
	out := bytes.Buffer{}
	must(download.SignatureCmd(ctx, regOpts, imgName, &out), t)

	// Create a new image to attach to
	img2Name := path.Join(repo, "sign-new-bundle-2")
	_, _, cleanup = mkimage(t, img2Name)
	defer cleanup()

	bundlePath := filepath.Join(td, "downloaded-bundle.sigstore.json")
	if err := os.WriteFile(bundlePath, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	must(attach.SignatureCmd(ctx, regOpts, "", bundlePath, "", "", "", "", img2Name), t)

	// Download should succeed on second image
	must(download.SignatureCmd(ctx, regOpts, img2Name, os.Stdout), t)
}

func TestAttachSBOM(t *testing.T) {
	td := t.TempDir()
	err := downloadAndSetEnv(t, rekorURL+"/api/v1/log/publicKey", env.VariableSigstoreRekorPublicKey.String(), td)
	if err != nil {
		t.Fatal(err)
	}

	repo, stop := reg(t)
	defer stop()
	ctx := context.Background()

	imgName := path.Join(repo, "sbom-image")
	img, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	out := bytes.Buffer{}

	_, errPl := download.SBOMCmd(ctx, options.RegistryOptions{}, options.SBOMDownloadOptions{Platform: "darwin/amd64"}, img.Name(), &out)
	if errPl == nil {
		t.Fatalf("Expected error when passing Platform to single arch image")
	}
	_, err = download.SBOMCmd(ctx, options.RegistryOptions{}, options.SBOMDownloadOptions{}, img.Name(), &out)
	if err == nil {
		t.Fatal("Expected error")
	}
	t.Log(out.String())
	out.Reset()

	// Upload it!
	must(attach.SBOMCmd(ctx, options.RegistryOptions{}, options.RegistryExperimentalOptions{}, "./testdata/bom-go-mod.spdx", "spdx", imgName), t)

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

	// Generate key pairs to sign the sbom
	td1 := t.TempDir()
	td2 := t.TempDir()
	_, privKeyPath1, pubKeyPath1 := keypair(t, td1)
	_, _, pubKeyPath2 := keypair(t, td2)

	// Verify should fail on a bad input
	mustErr(verify(pubKeyPath1, imgName, true, nil, "sbom", false), t)
	mustErr(verify(pubKeyPath2, imgName, true, nil, "sbom", false), t)

	// Now sign the sbom with one key
	ko1 := options.KeyOpts{
		KeyRef:   privKeyPath1,
		PassFunc: passFunc,
		RekorURL: rekorURL,
	}
	so := options.SignOptions{
		Upload:     true,
		TlogUpload: true,
		Attachment: "sbom",
	}
	must(sign.SignCmd(ctx, ro, ko1, so, []string{imgName}), t)

	// Now verify should work with that one, but not the other
	must(verify(pubKeyPath1, imgName, true, nil, "sbom", false), t)
	mustErr(verify(pubKeyPath2, imgName, true, nil, "sbom", false), t)
}

func TestNoTlog(t *testing.T) {
	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "cosign-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, pubKeyPath := keypair(t, td)

	// Verify should fail at first
	mustErr(verify(pubKeyPath, imgName, true, nil, "", true), t)

	// Now sign the image without the tlog
	ko := options.KeyOpts{
		KeyRef:   privKeyPath,
		PassFunc: passFunc,
		RekorURL: rekorURL,
	}
	so := options.SignOptions{
		Upload: true,
	}
	must(sign.SignCmd(t.Context(), ro, ko, so, []string{imgName}), t)

	// Now verify should work!
	must(verify(pubKeyPath, imgName, true, nil, "", true), t)
}

func TestGetPublicKeyCustomOut(t *testing.T) {
	td := t.TempDir()
	keys, privKeyPath, _ := keypair(t, td)
	ctx := context.Background()

	outFile := "output.pub"
	outPath := filepath.Join(td, outFile)
	outWriter, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE, 0o600)
	must(err, t)

	pk := publickey.Pkopts{
		KeyRef: privKeyPath,
	}
	must(publickey.GetPublicKey(ctx, pk, publickey.NamedWriter{Name: outPath, Writer: outWriter}, passFunc), t)

	output, err := os.ReadFile(outPath)
	must(err, t)
	equals(keys.PublicBytes, output, t)
}

// If a signature has a bundle, but *not for that signature*, cosign verification should fail.
// This test is pretty long, so here are the basic points:
//  1. Sign image1 with a keypair, store entry in rekor
//  2. Sign image2 with keypair, DO NOT store entry in rekor
//  3. Take the bundle from image1 and store it on the signature in image2
//  4. Verification of image2 should now fail, since the bundle is for a different signature
func TestInvalidBundle(t *testing.T) {
	td := t.TempDir()
	err := downloadAndSetEnv(t, rekorURL+"/api/v1/log/publicKey", env.VariableSigstoreRekorPublicKey.String(), td)
	if err != nil {
		t.Fatal(err)
	}

	regName, stop := reg(t)
	defer stop()

	img1 := path.Join(regName, "cosign-e2e")

	imgRef, _, cleanup := mkimage(t, img1)
	defer cleanup()

	_, privKeyPath, pubKeyPath := keypair(t, td)

	ctx := context.Background()

	// Sign image1 and store the entry in rekor
	// (we're just using it for its bundle)
	remoteOpts := ociremote.WithRemoteOptions(registryClientOpts(ctx)...)
	ko := options.KeyOpts{KeyRef: privKeyPath, PassFunc: passFunc, RekorURL: rekorURL}
	so := options.SignOptions{
		Upload:           true,
		TlogUpload:       true,
		SkipConfirmation: true,
	}
	must(sign.SignCmd(ctx, ro, ko, so, []string{img1}), t)
	// verify image1
	must(verify(pubKeyPath, img1, true, nil, "", false), t)
	// extract the bundle from image1
	si, err := ociremote.SignedImage(imgRef, remoteOpts)
	must(err, t)
	imgSigs, err := si.Signatures()
	must(err, t)
	sigs, err := imgSigs.Get()
	must(err, t)
	if l := len(sigs); l != 1 {
		t.Error("expected one signature")
	}
	bund, err := sigs[0].Bundle()
	must(err, t)
	if bund == nil {
		t.Fail()
	}

	// Now, we move on to image2
	// Sign image2 and DO NOT store the entry in rekor
	img2 := path.Join(regName, "unrelated")
	imgRef2, _, cleanup := mkimage(t, img2)
	defer cleanup()
	so = options.SignOptions{
		Upload:     true,
		TlogUpload: false,
	}
	must(sign.SignCmd(ctx, ro, ko, so, []string{img2}), t)
	must(verify(pubKeyPath, img2, true, nil, "", true), t)

	si2, err := ociremote.SignedEntity(imgRef2, remoteOpts)
	must(err, t)
	sigs2, err := si2.Signatures()
	must(err, t)
	gottenSigs2, err := sigs2.Get()
	must(err, t)
	if len(gottenSigs2) != 1 {
		t.Fatal("there should be one signature")
	}
	sigsTag, err := ociremote.SignatureTag(imgRef2)
	if err != nil {
		t.Fatal(err)
	}

	// At this point, we would mutate the signature to add the bundle annotation
	// since we don't have a function for it at the moment, mock this by deleting the signature
	// and pushing a new signature with the additional bundle annotation
	if err := remote.Delete(sigsTag); err != nil {
		t.Fatal(err)
	}
	mustErr(verify(pubKeyPath, img2, true, nil, "", false), t)

	newSig, err := mutate.Signature(gottenSigs2[0], mutate.WithBundle(bund))
	must(err, t)
	si2, err = ociremote.SignedEntity(imgRef2, remoteOpts)
	must(err, t)
	newImage, err := mutate.AttachSignatureToEntity(si2, newSig)
	must(err, t)
	if err := ociremote.WriteSignatures(sigsTag.Repository, newImage); err != nil {
		t.Fatal(err)
	}

	// veriyfing image2 now should fail
	cmd := cliverify.VerifyCommand{
		KeyRef:        pubKeyPath,
		RekorURL:      rekorURL,
		CheckClaims:   true,
		HashAlgorithm: crypto.SHA256,
		MaxWorkers:    10,
	}
	args := []string{img2}
	mustErr(cmd.Exec(context.Background(), args), t)
}

func TestAttestBlobSignVerify(t *testing.T) {
	blob := "someblob"
	predicate := `{ "buildType": "x", "builder": { "id": "2" }, "recipe": {} }`
	predicateType := "slsaprovenance"
	statement := `{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"someblob","digest":{"alg":"7e9b6e7ba2842c91cf49f3e214d04a7a496f8214356f41d81a6e6dcad11f11e3"}}],"predicateType":"something","predicate":{}}`

	td1 := t.TempDir()
	t.Cleanup(func() {
		os.RemoveAll(td1)
	})

	bp := filepath.Join(td1, blob)
	if err := os.WriteFile(bp, []byte(blob), 0o644); err != nil {
		t.Fatal(err)
	}

	anotherBlob := filepath.Join(td1, "another-blob")
	if err := os.WriteFile(anotherBlob, []byte("another-blob"), 0o644); err != nil {
		t.Fatal(err)
	}

	predicatePath := filepath.Join(td1, "predicate")
	if err := os.WriteFile(predicatePath, []byte(predicate), 0o644); err != nil {
		t.Fatal(err)
	}

	statementPath := filepath.Join(td1, "statement")
	if err := os.WriteFile(statementPath, []byte(statement), 0o644); err != nil {
		t.Fatal(err)
	}

	outputSignature := filepath.Join(td1, "signature")

	_, privKeyPath1, pubKeyPath1 := keypair(t, td1)

	ctx := context.Background()
	ko := options.KeyOpts{
		KeyRef: pubKeyPath1,
	}
	blobVerifyAttestationCmd := cliverify.VerifyBlobAttestationCommand{
		KeyOpts:       ko,
		SignaturePath: outputSignature,
		PredicateType: predicateType,
		IgnoreTlog:    true,
		CheckClaims:   true,
	}
	// Verify should fail on a bad input
	mustErr(blobVerifyAttestationCmd.Exec(ctx, bp), t)

	// Now attest the blob with the private key
	ko = options.KeyOpts{
		KeyRef:   privKeyPath1,
		PassFunc: passFunc,
	}
	attestBlobCmd := attest.AttestBlobCommand{
		KeyOpts:         ko,
		PredicatePath:   predicatePath,
		PredicateType:   predicateType,
		OutputSignature: outputSignature,
		RekorEntryType:  "dsse",
	}
	must(attestBlobCmd.Exec(ctx, bp), t)

	// Now verify should work
	must(blobVerifyAttestationCmd.Exec(ctx, bp), t)

	// Make sure we fail with the wrong predicate type
	blobVerifyAttestationCmd.PredicateType = "custom"
	mustErr(blobVerifyAttestationCmd.Exec(ctx, bp), t)

	// Make sure we fail with the wrong blob (set the predicate type back)
	blobVerifyAttestationCmd.PredicateType = predicateType
	mustErr(blobVerifyAttestationCmd.Exec(ctx, anotherBlob), t)

	// Test statement signing
	attestBlobCmd = attest.AttestBlobCommand{
		KeyOpts:         ko,
		StatementPath:   statementPath,
		OutputSignature: outputSignature,
		RekorEntryType:  "dsse",
	}
	must(attestBlobCmd.Exec(ctx, bp), t)

	// Test statement verification
	ko = options.KeyOpts{
		KeyRef: pubKeyPath1,
	}
	blobVerifyAttestationCmd = cliverify.VerifyBlobAttestationCommand{
		KeyOpts:       ko,
		Digest:        "7e9b6e7ba2842c91cf49f3e214d04a7a496f8214356f41d81a6e6dcad11f11e3",
		DigestAlg:     "alg",
		SignaturePath: outputSignature,
		IgnoreTlog:    true,
		PredicateType: "something",
	}
	must(blobVerifyAttestationCmd.Exec(ctx, bp), t)
}

func TestOffline(t *testing.T) {
	td := t.TempDir()
	err := downloadAndSetEnv(t, rekorURL+"/api/v1/log/publicKey", env.VariableSigstoreRekorPublicKey.String(), td)
	if err != nil {
		t.Fatal(err)
	}

	regName, stop := reg(t)
	defer stop()

	img1 := path.Join(regName, "cosign-e2e")

	imgRef, _, cleanup := mkimage(t, img1)
	defer cleanup()

	_, privKeyPath, pubKeyPath := keypair(t, td)

	ctx := context.Background()

	// Sign image1 and store the entry in rekor
	ko := options.KeyOpts{KeyRef: privKeyPath, PassFunc: passFunc, RekorURL: rekorURL}
	so := options.SignOptions{
		Upload:           true,
		TlogUpload:       true,
		SkipConfirmation: true,
	}
	must(sign.SignCmd(ctx, ro, ko, so, []string{img1}), t)
	// verify image1 online and offline
	must(verify(pubKeyPath, img1, true, nil, "", false), t)
	verifyCmd := &cliverify.VerifyCommand{
		KeyRef:      pubKeyPath,
		RekorURL:    "notreal",
		Offline:     true,
		CheckClaims: true,
		MaxWorkers:  10,
	}
	must(verifyCmd.Exec(ctx, []string{img1}), t)

	// Get signatures
	si, err := ociremote.SignedEntity(imgRef)
	must(err, t)
	sigs, err := si.Signatures()
	must(err, t)
	gottenSigs, err := sigs.Get()
	must(err, t)

	fakeBundle := &bundle.RekorBundle{
		SignedEntryTimestamp: []byte(""),
		Payload: bundle.RekorPayload{
			Body: "",
		},
	}
	newSig, err := mutate.Signature(gottenSigs[0], mutate.WithBundle(fakeBundle))
	must(err, t)

	sigsTag, err := ociremote.SignatureTag(imgRef)
	must(err, t)

	if err := remote.Delete(sigsTag); err != nil {
		t.Fatal(err)
	}

	si, err = ociremote.SignedEntity(imgRef)
	must(err, t)
	newImage, err := mutate.AttachSignatureToEntity(si, newSig)
	must(err, t)

	mustErr(verify(pubKeyPath, img1, true, nil, "", false), t)
	if err := ociremote.WriteSignatures(sigsTag.Repository, newImage); err != nil {
		t.Fatal(err)
	}

	// Confirm offline verification fails
	mustErr(verifyCmd.Exec(ctx, []string{img1}), t)
}

func TestDockerfileVerify(t *testing.T) {
	td := t.TempDir()

	// set up SIGSTORE_ variables to point to keys for the local instances
	err := setLocalEnv(t, td)
	if err != nil {
		t.Fatal(err)
	}

	// unset the roots that were generated for timestamp signing, they won't work here
	err = fulcioroots.ReInit()
	if err != nil {
		t.Fatal(err)
	}

	identityToken, err := getOIDCToken()
	if err != nil {
		t.Fatal(err)
	}

	// create some images
	repo, stop := reg(t)
	defer stop()
	signedImg1 := path.Join(repo, "cosign-e2e-dockerfile-signed1")
	_, _, cleanup1 := mkimage(t, signedImg1)
	defer cleanup1()
	signedImg2 := path.Join(repo, "cosign-e2e-dockerfile-signed2")
	_, _, cleanup2 := mkimage(t, signedImg2)
	defer cleanup2()
	unsignedImg := path.Join(repo, "cosign-e2e-dockerfile-unsigned")
	_, _, cleanupUnsigned := mkimage(t, unsignedImg)
	defer cleanupUnsigned()

	// sign the images using --identity-token
	ko := options.KeyOpts{
		FulcioURL:        fulcioURL,
		RekorURL:         rekorURL,
		IDToken:          identityToken,
		SkipConfirmation: true,
	}
	so := options.SignOptions{
		Upload:           true,
		TlogUpload:       true,
		SkipConfirmation: true,
	}
	ctx := context.Background()
	must(sign.SignCmd(ctx, ro, ko, so, []string{signedImg1}), t)
	must(sign.SignCmd(ctx, ro, ko, so, []string{signedImg2}), t)

	// create the dockerfiles
	singleStageDockerfileContents := fmt.Sprintf(`
FROM %s
`, signedImg1)
	singleStageDockerfile := mkfile(singleStageDockerfileContents, td, t)

	unsignedBuildStageDockerfileContents := fmt.Sprintf(`
FROM %s

FROM %s

FROM %s
`, signedImg1, unsignedImg, signedImg2)
	unsignedBuildStageDockerfile := mkfile(unsignedBuildStageDockerfileContents, td, t)

	fromAsDockerfileContents := fmt.Sprintf(`
FROM --platform=linux/amd64 %s AS base
`, signedImg1)
	fromAsDockerfile := mkfile(fromAsDockerfileContents, td, t)

	withArgDockerfileContents := `
ARG test_image

FROM ${test_image}
`
	withArgDockerfile := mkfile(withArgDockerfileContents, td, t)

	withLowercaseDockerfileContents := fmt.Sprintf(`
from %s
`, signedImg1)
	withLowercaseDockerfile := mkfile(withLowercaseDockerfileContents, td, t)

	issuer := os.Getenv("OIDC_URL")

	tests := []struct {
		name       string
		dockerfile string
		baseOnly   bool
		env        map[string]string
		wantErr    bool
	}{
		{
			name:       "verify single stage",
			dockerfile: singleStageDockerfile,
		},
		{
			name:       "verify unsigned build stage",
			dockerfile: unsignedBuildStageDockerfile,
			wantErr:    true,
		},
		{
			name:       "verify base image only",
			dockerfile: unsignedBuildStageDockerfile,
			baseOnly:   true,
		},
		{
			name:       "verify from as",
			dockerfile: fromAsDockerfile,
		},
		{
			name:       "verify with arg",
			dockerfile: withArgDockerfile,
			env:        map[string]string{"test_image": signedImg1},
		},
		{
			name:       "verify image exists but is unsigned",
			dockerfile: withArgDockerfile,
			env:        map[string]string{"test_image": unsignedImg},
			wantErr:    true,
		},
		{
			name:       "verify with lowercase",
			dockerfile: withLowercaseDockerfile,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := dockerfile.VerifyDockerfileCommand{
				VerifyCommand: cliverify.VerifyCommand{
					CertVerifyOptions: options.CertVerifyOptions{
						CertOidcIssuer: issuer,
						CertIdentity:   certID,
					},
					RekorURL: rekorURL,
				},
				BaseOnly: test.baseOnly,
			}
			args := []string{test.dockerfile}
			for k, v := range test.env {
				t.Setenv(k, v)
			}
			if test.wantErr {
				mustErr(cmd.Exec(ctx, args), t)
			} else {
				must(cmd.Exec(ctx, args), t)
			}
		})
	}
}

func TestManifestVerify(t *testing.T) {
	td := t.TempDir()

	// set up SIGSTORE_ variables to point to keys for the local instances
	err := setLocalEnv(t, td)
	if err != nil {
		t.Fatal(err)
	}

	// unset the roots that were generated for timestamp signing, they won't work here
	err = fulcioroots.ReInit()
	if err != nil {
		t.Fatal(err)
	}

	identityToken, err := getOIDCToken()
	if err != nil {
		t.Fatal(err)
	}

	// create some images
	repo, stop := reg(t)
	defer stop()
	signedImg := path.Join(repo, "cosign-e2e-manifest-signed")
	_, _, cleanup := mkimage(t, signedImg)
	defer cleanup()
	unsignedImg := path.Join(repo, "cosign-e2e-manifest-unsigned")
	_, _, cleanupUnsigned := mkimage(t, unsignedImg)
	defer cleanupUnsigned()

	// sign the images using --identity-token
	ko := options.KeyOpts{
		FulcioURL:        fulcioURL,
		RekorURL:         rekorURL,
		IDToken:          identityToken,
		SkipConfirmation: true,
	}
	so := options.SignOptions{
		Upload:           true,
		TlogUpload:       true,
		SkipConfirmation: true,
	}
	ctx := context.Background()
	must(sign.SignCmd(ctx, ro, ko, so, []string{signedImg}), t)

	// create the manifests
	manifestTemplate := `
apiVersion: v1
kind: Pod
metadata:
  name: single-pod
spec:
  containers:
    - name: %s
      image: %s
`
	signedManifestContents := fmt.Sprintf(manifestTemplate, "signed-img", signedImg)
	signedManifest := mkfileWithExt(signedManifestContents, td, ".yaml", t)
	unsignedManifestContents := fmt.Sprintf(manifestTemplate, "unsigned-img", unsignedImg)
	unsignedManifest := mkfileWithExt(unsignedManifestContents, td, ".yaml", t)

	issuer := os.Getenv("OIDC_URL")

	tests := []struct {
		name     string
		manifest string
		wantErr  bool
	}{
		{
			name:     "signed manifest",
			manifest: signedManifest,
		},
		{
			name:     "unsigned manifest",
			manifest: unsignedManifest,
			wantErr:  true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := manifest.VerifyManifestCommand{
				VerifyCommand: cliverify.VerifyCommand{
					CertVerifyOptions: options.CertVerifyOptions{
						CertOidcIssuer: issuer,
						CertIdentity:   certID,
					},
					RekorURL: rekorURL,
				},
			}
			args := []string{test.manifest}
			if test.wantErr {
				mustErr(cmd.Exec(ctx, args), t)
			} else {
				must(cmd.Exec(ctx, args), t)
			}
		})
	}
}

// getOIDCToken gets an OIDC token from the mock OIDC server.
func getOIDCToken() (string, error) {
	issuer := os.Getenv("OIDC_URL")
	resp, err := http.Get(issuer + "/token")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func TestSignVerifyWithRepoOverride(t *testing.T) {
	cosignRepo := env.Getenv(env.VariableRepository)
	if cosignRepo == "" {
		t.Skip("Skipping COSIGN_REPOSITORY test because a second repository and COSIGN_REPOSITORY must be set up")
	}
	td := t.TempDir()
	err := downloadAndSetEnv(t, rekorURL+"/api/v1/log/publicKey", env.VariableSigstoreRekorPublicKey.String(), td)
	if err != nil {
		t.Fatal(err)
	}

	repo, stop := reg(t)
	defer stop()

	imgName := path.Join(repo, "cosign-e2e")

	name, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	digest, err := crane.Digest(name.String())
	must(err, t)

	_, privKeyPath, pubKeyPath := keypair(t, td)

	// Verify should fail at first
	mustErr(verify(pubKeyPath, imgName, true, nil, "", false), t)

	// No artifacts yet in the second registry
	_, err = crane.ListTags(cosignRepo)
	mustErr(err, t)

	// Only one tag in the first registry
	tags, err := crane.ListTags(name.String())
	must(err, t)
	assert.Len(t, tags, 1, "expected 1 tag in the first repo")
	assert.Equal(t, tags[0], "latest", "expected tag name to be 'latest'")

	// Now sign the image

	ko := options.KeyOpts{
		KeyRef:           privKeyPath,
		PassFunc:         passFunc,
		RekorURL:         rekorURL,
		SkipConfirmation: true,
	}

	so := options.SignOptions{
		Upload:     true,
		TlogUpload: true,
	}

	must(sign.SignCmd(t.Context(), ro, ko, so, []string{imgName}), t)

	// Bundle should appear in the second repo
	tags, err = crane.ListTags(cosignRepo)
	must(err, t)
	assert.Len(t, tags, 1, "expected 1 signature tag in the second repo")
	expectedTagName := fmt.Sprintf("%s.sig", strings.ReplaceAll(digest, ":", "-"))
	assert.Equal(t, tags[0], expectedTagName, "expected signature tag to match sha256-<digest>.sig")
	// but not in the first repo
	tags, err = crane.ListTags(name.String())
	must(err, t)
	assert.Len(t, tags, 1, "expected no extra tags in the first repo")
	assert.Equal(t, tags[0], "latest", "expected tag name to be 'latest'")

	// Now verify and download should work!
	must(verify(pubKeyPath, imgName, true, nil, "", false), t)

	// Sign another image with the new protobuf bundle format
	so.NewBundleFormat = true
	must(sign.SignCmd(t.Context(), ro, ko, so, []string{name.String()}), t)

	// The new bundle should appear under a new tag for the second repo
	tags, err = crane.ListTags(cosignRepo)
	must(err, t)
	assert.Len(t, tags, 2, "expected new tag in the second repo")
	expectedTagName = strings.ReplaceAll(digest, ":", "-")
	assert.Equal(t, tags[0], expectedTagName, "expected new tag to match referrers format")
	// but not in the first repo
	tags, err = crane.ListTags(name.String())
	must(err, t)
	assert.Len(t, tags, 1, "expected no extra tags in the first repo")
	assert.Equal(t, tags[0], "latest", "expected tag name to be 'latest'")

	// Verify should work with new bundle format
	cmd := cliverify.VerifyCommand{
		KeyRef:          pubKeyPath,
		RekorURL:        rekorURL,
		NewBundleFormat: true,
	}

	ctx := context.Background()
	must(cmd.Exec(ctx, []string{imgName}), t)
}

func TestSignVerifyMultipleIdentities(t *testing.T) {
	td := t.TempDir()
	err := downloadAndSetEnv(t, rekorURL+"/api/v1/log/publicKey", env.VariableSigstoreRekorPublicKey.String(), td)
	if err != nil {
		t.Fatal(err)
	}

	repo, stop := reg(t)
	defer stop()

	imgName := path.Join(repo, "cosign-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, pubKeyPath := keypair(t, td)

	// Verify should fail at first
	mustErr(verify(pubKeyPath, imgName, true, nil, "", false), t)

	// Now sign the image with multiple container identities
	ko := options.KeyOpts{
		KeyRef:           privKeyPath,
		PassFunc:         passFunc,
		RekorURL:         rekorURL,
		SkipConfirmation: true,
	}
	so := options.SignOptions{
		Upload:                  true,
		TlogUpload:              true,
		SignContainerIdentities: []string{"registry/cosign-e2e:tag1", "registry/cosign-e2e:tag2"},
	}
	must(sign.SignCmd(t.Context(), ro, ko, so, []string{imgName}), t)

	// Now verify should work
	must(verify(pubKeyPath, imgName, true, nil, "", false), t)
}

func TestTree(t *testing.T) {
	repo, stop := reg(t)
	defer stop()

	imgName := path.Join(repo, "tree")
	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	// Test out tree command before
	ctx := context.Background()
	regOpts := options.RegistryOptions{}
	regExpOpts := options.RegistryExperimentalOptions{}
	out := bytes.Buffer{}

	must(cli.TreeCmd(ctx, regOpts, regExpOpts, true, imgName, &out), t)
	assert.False(t, strings.Contains(out.String(), "https://sigstore.dev/cosign/sign/v1"))

	// Sign the image
	td := t.TempDir()
	_, privKeyPath, _ := keypair(t, td)
	ko := options.KeyOpts{KeyRef: privKeyPath, PassFunc: passFunc}
	so := options.SignOptions{
		NewBundleFormat: true,
		Upload:          true,
	}

	must(sign.SignCmd(t.Context(), ro, ko, so, []string{imgName}), t)

	// Test out tree command after sign
	out.Reset()
	must(cli.TreeCmd(ctx, regOpts, regExpOpts, true, imgName, &out), t)
	assert.True(t, strings.Contains(out.String(), "https://sigstore.dev/cosign/sign/v1"))
}

func TestSignVerifyUploadFalse(t *testing.T) {
	td := t.TempDir()
	ctx := context.Background()

	repo, stop := reg(t)
	defer stop()

	imgName := path.Join(repo, "cosign-e2e-no-upload")
	name, desc, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, _ := keypair(t, td)

	regOpts := options.RegistryOptions{}
	regExpOpts := options.RegistryExperimentalOptions{}
	out := bytes.Buffer{}

	// There should be no signatures yet
	must(cli.TreeCmd(ctx, regOpts, regExpOpts, true, imgName, &out), t)
	assert.Contains(t, out.String(), "No Supply Chain Security Related Artifacts found for image")

	// Now sign the image with Upload: false
	ko := options.KeyOpts{
		KeyRef:           privKeyPath,
		PassFunc:         passFunc,
		SkipConfirmation: true,
	}
	so := options.SignOptions{
		Upload: false,
	}
	must(sign.SignCmd(t.Context(), ro, ko, so, []string{imgName}), t)

	// There should still be no signatures
	out.Reset()
	must(cli.TreeCmd(ctx, regOpts, regExpOpts, true, imgName, &out), t)
	assert.Contains(t, out.String(), "No Supply Chain Security Related Artifacts found for image")

	// Now with Upload: true
	so.Upload = true
	must(sign.SignCmd(t.Context(), ro, ko, so, []string{imgName}), t)

	// Now there should be signatures
	out.Reset()
	must(cli.TreeCmd(ctx, regOpts, regExpOpts, true, imgName, &out), t)
	assert.Contains(t, out.String(), fmt.Sprintf("Signatures for an image tag: %s:%s-%s.sig", name, desc.Digest.Algorithm, desc.Digest.Hex))

	// Try on a new image with new bundle format
	imgName = path.Join(repo, "cosign-e2e-no-upload-bundle")
	name2, _, cleanup2 := mkimage(t, imgName)
	defer cleanup2()

	// There should be no signatures yet
	out.Reset()
	must(cli.TreeCmd(ctx, regOpts, regExpOpts, true, imgName, &out), t)
	assert.Contains(t, out.String(), "No Supply Chain Security Related Artifacts found for image")

	// Now sign the image with Upload: false
	so.Upload = false
	so.NewBundleFormat = true
	so.BundlePath = path.Join(td, "output.bundle")
	must(sign.SignCmd(t.Context(), ro, ko, so, []string{imgName}), t)
	assert.FileExists(t, so.BundlePath)

	// There should still be no signatures
	out.Reset()
	must(cli.TreeCmd(ctx, regOpts, regExpOpts, true, imgName, &out), t)
	assert.Contains(t, out.String(), "No Supply Chain Security Related Artifacts found for image")

	// Now with Upload: true
	so.Upload = true
	must(sign.SignCmd(t.Context(), ro, ko, so, []string{imgName}), t)

	// Now there should be signatures
	out.Reset()
	must(cli.TreeCmd(ctx, regOpts, regExpOpts, true, imgName, &out), t)
	assert.Regexp(t, regexp.MustCompile(fmt.Sprintf("https://sigstore.dev/cosign/sign/v1 artifacts via OCI referrer: %s@sha256:[a-z0-9]*\n", name2)), out.String())
	assert.FileExists(t, so.BundlePath)
	f, err := os.Open(so.BundlePath)
	must(err, t)
	defer f.Close()
	h := sha256.New()
	_, err = io.Copy(h, f)
	must(err, t)
	assert.Contains(t, out.String(), fmt.Sprintf("sha256:%s", hex.EncodeToString(h.Sum(nil))))
}

func TestAttestVerifyUploadFalse(t *testing.T) {
	td := t.TempDir()
	ctx := context.Background()

	repo, stop := reg(t)
	defer stop()

	imgName := path.Join(repo, "cosign-e2e-no-upload")
	name, desc, cleanup := mkimage(t, imgName)
	defer cleanup()

	_, privKeyPath, _ := keypair(t, td)

	regOpts := options.RegistryOptions{}
	regExpOpts := options.RegistryExperimentalOptions{}
	out := bytes.Buffer{}

	// There should be no attestations yet
	must(cli.TreeCmd(ctx, regOpts, regExpOpts, true, imgName, &out), t)
	assert.Contains(t, out.String(), "No Supply Chain Security Related Artifacts found for image")

	// Now attest the image with NoUpload: true
	ko := options.KeyOpts{
		KeyRef:           privKeyPath,
		PassFunc:         passFunc,
		SkipConfirmation: true,
	}
	predicate := `{ "buildType": "x", "builder": { "id": "2" }, "recipe": {} }`
	predicatePath := filepath.Join(t.TempDir(), "predicate.json")
	if err := os.WriteFile(predicatePath, []byte(predicate), 0o644); err != nil {
		t.Fatal(err)
	}
	attestCmd := attest.AttestCommand{
		KeyOpts:        ko,
		PredicatePath:  predicatePath,
		PredicateType:  "slsaprovenance",
		RekorEntryType: "dsse",
		NoUpload:       true,
	}
	must(attestCmd.Exec(ctx, imgName), t)

	// There should still be no attestations
	out.Reset()
	must(cli.TreeCmd(ctx, regOpts, regExpOpts, true, imgName, &out), t)
	assert.Contains(t, out.String(), "No Supply Chain Security Related Artifacts found for image")

	// Now with NoUpload: false
	attestCmd.NoUpload = false
	must(attestCmd.Exec(ctx, imgName), t)

	// Now there should be attestations
	out.Reset()
	must(cli.TreeCmd(ctx, regOpts, regExpOpts, true, imgName, &out), t)
	assert.Contains(t, out.String(), fmt.Sprintf("Attestations for an image tag: %s:%s-%s.att", name, desc.Digest.Algorithm, desc.Digest.Hex))

	// Try on a new image with new bundle format
	imgName = path.Join(repo, "cosign-e2e-no-upload-bundle")
	name2, _, cleanup2 := mkimage(t, imgName)
	defer cleanup2()

	// There should be no attestations yet
	out.Reset()
	must(cli.TreeCmd(ctx, regOpts, regExpOpts, true, imgName, &out), t)
	assert.Contains(t, out.String(), "No Supply Chain Security Related Artifacts found for image")

	// Now attest the image with NoUpload: true
	attestCmd.NoUpload = true
	attestCmd.NewBundleFormat = true
	attestCmd.BundlePath = path.Join(td, "output.bundle")
	must(attestCmd.Exec(ctx, imgName), t)
	assert.FileExists(t, attestCmd.BundlePath)

	// There should still be no attestations
	out.Reset()
	must(cli.TreeCmd(ctx, regOpts, regExpOpts, true, imgName, &out), t)
	assert.Contains(t, out.String(), "No Supply Chain Security Related Artifacts found for image")

	// Now with NoUpload: true
	attestCmd.NoUpload = false
	must(attestCmd.Exec(ctx, imgName), t)

	// Now there should be attestations
	out.Reset()
	must(cli.TreeCmd(ctx, regOpts, regExpOpts, true, imgName, &out), t)
	assert.Regexp(t, regexp.MustCompile(fmt.Sprintf("https://slsa.dev/provenance/v0.2 artifacts via OCI referrer: %s@sha256:[a-z0-9]*\n", name2)), out.String())
	assert.FileExists(t, attestCmd.BundlePath)
	f, err := os.Open(attestCmd.BundlePath)
	must(err, t)
	defer f.Close()
	h := sha256.New()
	_, err = io.Copy(h, f)
	must(err, t)
	assert.Contains(t, out.String(), fmt.Sprintf("sha256:%s", hex.EncodeToString(h.Sum(nil))))
}

func selfSignedCertificate() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	ct := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "self.signed.cert",
			Organization: []string{"dev"},
		},
		EmailAddresses: []string{"foo@bar.com"},
		NotBefore:      time.Now().Add(-1 * time.Minute),
		NotAfter:       time.Now().Add(24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, ct, ct, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, priv, nil
}
