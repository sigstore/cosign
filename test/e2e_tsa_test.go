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
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/encrypted"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/sign"
	cliverify "github.com/sigstore/cosign/v3/cmd/cosign/cli/verify"
	cert_test "github.com/sigstore/cosign/v3/internal/test"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	tsaclient "github.com/sigstore/timestamp-authority/v2/pkg/client"
	tsaserver "github.com/sigstore/timestamp-authority/v2/pkg/server"
	"github.com/spf13/viper"

	prototrustroot "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
)

func TestTSAMTLS(t *testing.T) {
	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "cosign-tsa-mtls-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	pemRootRef, pemLeafRef, pemKeyRef := generateSigningKeys(t, td)

	// Set up TSA server with TLS
	timestampCACert, timestampServerCert, timestampServerKey, timestampClientCert, timestampClientKey := generateMTLSKeys(t, td)
	timestampServerURL, timestampChainFile, tsaCleanup := setUpTSAServerWithTLS(t, td, timestampCACert, timestampServerKey, timestampServerCert)
	t.Cleanup(tsaCleanup)

	ko := options.KeyOpts{
		KeyRef:          pemKeyRef,
		PassFunc:        passFunc,
		RekorVersion:    1,
		TSAServerURL:    timestampServerURL,
		TSAClientCACert: timestampCACert,
		TSAClientCert:   timestampClientCert,
		TSAClientKey:    timestampClientKey,
		TSAServerName:   "server.example.com",
	}
	so := options.SignOptions{
		Upload:     true,
		TlogUpload: false,
		Cert:       pemLeafRef,
		CertChain:  pemRootRef,
	}
	must(sign.SignCmd(t.Context(), ro, ko, so, []string{imgName}), t)

	verifyCmd := cliverify.VerifyCommand{
		IgnoreTlog:       true,
		IgnoreSCT:        true,
		CheckClaims:      true,
		CertChain:        pemRootRef,
		TSACertChainPath: timestampChainFile,
		CertVerifyOptions: options.CertVerifyOptions{
			CertIdentityRegexp:   ".*",
			CertOidcIssuerRegexp: ".*",
		},
	}
	must(verifyCmd.Exec(context.Background(), []string{imgName}), t)
}

func TestSignBlobTSAMTLS(t *testing.T) {
	td := t.TempDir()
	blob := time.Now().Format("Mon Jan 2 15:04:05 MST 2006")
	blobPath := mkfile(blob, td, t)
	timestampPath := filepath.Join(td, "timestamp.txt")
	bundlePath := filepath.Join(td, "cosign.bundle")

	_, privKey, pubKey := keypair(t, td)

	// Set up TSA server with TLS
	timestampCACert, timestampServerCert, timestampServerKey, timestampClientCert, timestampClientKey := generateMTLSKeys(t, td)
	timestampServerURL, timestampChainFile, tsaCleanup := setUpTSAServerWithTLS(t, td, timestampCACert, timestampServerKey, timestampServerCert)
	t.Cleanup(tsaCleanup)

	signingKO := options.KeyOpts{
		KeyRef:               privKey,
		PassFunc:             passFunc,
		RekorVersion:         1,
		TSAServerURL:         timestampServerURL,
		TSAClientCACert:      timestampCACert,
		TSAClientCert:        timestampClientCert,
		TSAClientKey:         timestampClientKey,
		TSAServerName:        "server.example.com",
		RFC3161TimestampPath: timestampPath,
		BundlePath:           bundlePath,
	}
	sig, err := sign.SignBlobCmd(t.Context(), ro, signingKO, blobPath, "", "", true, "", "", false)
	must(err, t)

	verifyKO := options.KeyOpts{
		KeyRef:               pubKey,
		RekorVersion:         1,
		TSACertChainPath:     timestampChainFile,
		RFC3161TimestampPath: timestampPath,
		BundlePath:           bundlePath,
	}

	verifyCmd := cliverify.VerifyBlobCmd{
		KeyOpts: verifyKO,
		SigRef:  string(sig),
		CertVerifyOptions: options.CertVerifyOptions{
			CertIdentityRegexp:   ".*",
			CertOidcIssuerRegexp: ".*",
		},
		IgnoreTlog: true,
	}
	must(verifyCmd.Exec(context.Background(), blobPath), t)
}

func TestSignBlobTSAMTLSWithSigningConfig(t *testing.T) {
	td := t.TempDir()
	blob := time.Now().Format("Mon Jan 2 15:04:05 MST 2006")
	blobPath := mkfile(blob, td, t)
	bundlePath := filepath.Join(td, "cosign.bundle")

	_, privKey, pubKey := keypair(t, td)

	// Set up TSA server with TLS
	timestampCACert, timestampServerCert, timestampServerKey, timestampClientCert, timestampClientKey := generateMTLSKeys(t, td)
	timestampServerURL, timestampChainFile, tsaCleanup := setUpTSAServerWithTLS(t, td, timestampCACert, timestampServerKey, timestampServerCert)
	t.Cleanup(tsaCleanup)

	// Create SigningConfig
	tsaService := root.Service{
		URL:                 timestampServerURL,
		MajorAPIVersion:     1,
		Operator:            "test-operator",
		ValidityPeriodStart: time.Now().Add(-1 * time.Hour),
	}

	signingConfig, err := root.NewSigningConfig(
		root.SigningConfigMediaType02,
		nil, nil, nil, root.ServiceConfiguration{},
		[]root.Service{tsaService},
		root.ServiceConfiguration{Selector: prototrustroot.ServiceSelector_ANY},
	)
	must(err, t)

	// Create TrustedRoot with TSA CA
	chainBytes, err := os.ReadFile(timestampChainFile)
	must(err, t)

	var certs []*x509.Certificate
	for block, rest := pem.Decode(chainBytes); block != nil; block, rest = pem.Decode(rest) {
		cert, err := x509.ParseCertificate(block.Bytes)
		must(err, t)
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		t.Fatal("no certs found in timestamp chain file")
	}

	var intermediates []*x509.Certificate
	if len(certs) > 1 {
		intermediates = certs[1 : len(certs)-1]
	}

	tsaAuth := &root.SigstoreTimestampingAuthority{
		Root:                certs[len(certs)-1],
		Leaf:                certs[0],
		Intermediates:       intermediates,
		ValidityPeriodStart: certs[0].NotBefore,
		URI:                 timestampServerURL,
	}

	trustedRoot, err := root.NewTrustedRoot(
		root.TrustedRootMediaType01,
		nil,
		nil,
		[]root.TimestampingAuthority{tsaAuth},
		nil,
	)
	must(err, t)

	signingKO := options.KeyOpts{
		KeyRef:          privKey,
		PassFunc:        passFunc,
		RekorVersion:    1,
		TSAClientCACert: timestampCACert,
		TSAClientCert:   timestampClientCert,
		TSAClientKey:    timestampClientKey,
		TSAServerName:   "server.example.com",
		BundlePath:      bundlePath,
		SigningConfig:   signingConfig,
		TrustedMaterial: trustedRoot,
		NewBundleFormat: true,
	}
	_, err = sign.SignBlobCmd(t.Context(), ro, signingKO, blobPath, "", "", true, "", "", false)
	must(err, t)

	verifyKO := options.KeyOpts{
		KeyRef:          pubKey,
		RekorVersion:    1,
		BundlePath:      bundlePath,
		TrustedMaterial: trustedRoot,
		NewBundleFormat: true,
	}

	verifyCmd := cliverify.VerifyBlobCmd{
		KeyOpts: verifyKO,
		CertVerifyOptions: options.CertVerifyOptions{
			CertIdentityRegexp:   ".*",
			CertOidcIssuerRegexp: ".*",
		},
		IgnoreTlog: true,
	}
	must(verifyCmd.Exec(context.Background(), blobPath), t)
}

func TestTSAMTLSWithSigningConfig(t *testing.T) {
	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()

	imgName := path.Join(repo, "cosign-tsa-mtls-e2e")

	_, _, cleanup := mkimage(t, imgName)
	defer cleanup()

	pemRootRef, pemLeafRef, pemKeyRef := generateSigningKeys(t, td)

	// Set up TSA server with TLS
	timestampCACert, timestampServerCert, timestampServerKey, timestampClientCert, timestampClientKey := generateMTLSKeys(t, td)
	timestampServerURL, timestampChainFile, tsaCleanup := setUpTSAServerWithTLS(t, td, timestampCACert, timestampServerKey, timestampServerCert)
	t.Cleanup(tsaCleanup)

	// Create SigningConfig
	tsaService := root.Service{
		URL:                 timestampServerURL,
		MajorAPIVersion:     1,
		Operator:            "test-operator",
		ValidityPeriodStart: time.Now().Add(-1 * time.Hour),
	}

	signingConfig, err := root.NewSigningConfig(
		root.SigningConfigMediaType02,
		nil, nil, nil, root.ServiceConfiguration{},
		[]root.Service{tsaService},
		root.ServiceConfiguration{Selector: prototrustroot.ServiceSelector_ANY},
	)
	must(err, t)

	// Create TrustedRoot with TSA CA
	chainBytes, err := os.ReadFile(timestampChainFile)
	must(err, t)

	var certs []*x509.Certificate
	for block, rest := pem.Decode(chainBytes); block != nil; block, rest = pem.Decode(rest) {
		cert, err := x509.ParseCertificate(block.Bytes)
		must(err, t)
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		t.Fatal("no certs found in timestamp chain file")
	}

	var intermediates []*x509.Certificate
	if len(certs) > 1 {
		intermediates = certs[1 : len(certs)-1]
	}

	tsaAuth := &root.SigstoreTimestampingAuthority{
		Root:                certs[len(certs)-1],
		Leaf:                certs[0],
		Intermediates:       intermediates,
		ValidityPeriodStart: certs[0].NotBefore,
		URI:                 timestampServerURL,
	}

	// Add CA from pemRootRef
	caBytes, err := os.ReadFile(pemRootRef)
	must(err, t)
	var caCerts []*x509.Certificate
	for block, rest := pem.Decode(caBytes); block != nil; block, rest = pem.Decode(rest) {
		cert, err := x509.ParseCertificate(block.Bytes)
		must(err, t)
		caCerts = append(caCerts, cert)
	}
	if len(caCerts) == 0 {
		t.Fatal("no certs in pemRootRef")
	}
	caAuth := &root.FulcioCertificateAuthority{
		Root:                caCerts[0],
		ValidityPeriodStart: caCerts[0].NotBefore,
	}

	trustedRoot, err := root.NewTrustedRoot(
		root.TrustedRootMediaType01,
		[]root.CertificateAuthority{caAuth},
		nil,
		[]root.TimestampingAuthority{tsaAuth},
		nil,
	)
	must(err, t)

	ko := options.KeyOpts{
		KeyRef:          pemKeyRef,
		PassFunc:        passFunc,
		RekorVersion:    1,
		TSAClientCACert: timestampCACert,
		TSAClientCert:   timestampClientCert,
		TSAClientKey:    timestampClientKey,
		TSAServerName:   "server.example.com",
		SigningConfig:   signingConfig,
		TrustedMaterial: trustedRoot,
		NewBundleFormat: true,
	}
	so := options.SignOptions{
		Upload:          true,
		TlogUpload:      false,
		Cert:            pemLeafRef,
		CertChain:       pemRootRef,
		NewBundleFormat: true,
	}
	must(sign.SignCmd(t.Context(), ro, ko, so, []string{imgName}), t)

	trBytes, err := trustedRoot.MarshalJSON()
	must(err, t)
	trustedRootFile := mkfile(string(trBytes), td, t)

	verifyCmd := cliverify.VerifyCommand{
		IgnoreTlog:      true,
		IgnoreSCT:       true,
		CheckClaims:     true,
		NewBundleFormat: true,
		CommonVerifyOptions: options.CommonVerifyOptions{
			TrustedRootPath: trustedRootFile,
		},
		CertVerifyOptions: options.CertVerifyOptions{
			CertIdentityRegexp:   ".*",
			CertOidcIssuerRegexp: ".*",
		},
	}
	must(verifyCmd.Exec(context.Background(), []string{imgName}), t)
}

func generateSigningKeys(t *testing.T, td string) (string, string, string) {
	rootCert, rootKey, _ := cert_test.GenerateRootCa()
	pemRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Raw})
	pemRootRef := mkfile(string(pemRoot), td, t)

	leafCert, privKey, _ := cert_test.GenerateLeafCert("xyz@nosuchprovider.com", "oidc-issuer", rootCert, rootKey)
	pemLeaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Raw})
	pemLeafRef := mkfile(string(pemLeaf), td, t)

	x509Encoded, _ := x509.MarshalPKCS8PrivateKey(privKey)
	encBytes, _ := encrypted.Encrypt(x509Encoded, keyPass)
	keyPem := pem.EncodeToMemory(&pem.Block{
		Type:  cosign.CosignPrivateKeyPemType,
		Bytes: encBytes,
	})
	pemKeyRef := mkfile(string(keyPem), td, t)

	return pemRootRef, pemLeafRef, pemKeyRef
}

func generateMTLSKeys(t *testing.T, td string) (string, string, string, string, string) {
	rootCert, rootKey, _ := cert_test.GenerateRootCa()
	pemRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Raw})
	pemRootRef := mkfile(string(pemRoot), td, t)

	serverLeafCert, serverPrivKey, _ := cert_test.GenerateLeafCertWithSubjectAlternateNames([]string{"server.example.com"}, nil, nil, nil, "oidc-issuer", rootCert, rootKey)
	serverPemLeaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverLeafCert.Raw})
	serverPemLeafRef := mkfile(string(serverPemLeaf), td, t)
	serverX509Encoded, _ := x509.MarshalPKCS8PrivateKey(serverPrivKey)
	serverKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  cosign.ECPrivateKeyPemType,
		Bytes: serverX509Encoded,
	})
	serverPemKeyRef := mkfile(string(serverKeyPem), td, t)

	clientLeafCert, clientPrivKey, _ := cert_test.GenerateLeafCert("tsa-mtls-client", "oidc-issuer", rootCert, rootKey)
	clientPemLeaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientLeafCert.Raw})
	clientPemLeafRef := mkfile(string(clientPemLeaf), td, t)
	clientX509Encoded, _ := x509.MarshalPKCS8PrivateKey(clientPrivKey)
	clientKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  cosign.ECPrivateKeyPemType,
		Bytes: clientX509Encoded,
	})
	clientPemKeyRef := mkfile(string(clientKeyPem), td, t)
	return pemRootRef, serverPemLeafRef, serverPemKeyRef, clientPemLeafRef, clientPemKeyRef
}

func setUpTSAServerWithTLS(t *testing.T, td, timestampCACert, timestampServerKey, timestampServerCert string) (string, string, func()) {
	viper.Set("timestamp-signer", "memory")
	viper.Set("timestamp-signer-hash", "sha256")
	viper.Set("disable-ntp-monitoring", true)
	viper.Set("tls-host", "0.0.0.0")
	viper.Set("tls-port", 3000)
	viper.Set("tls-ca", timestampCACert)
	viper.Set("tls-key", timestampServerKey)
	viper.Set("tls-certificate", timestampServerCert)
	tsaAPIServer := tsaserver.NewRestAPIServer("localhost", 3000, []string{"https"}, false, 10*time.Second, 10*time.Second)
	tsaServer := httptest.NewServer(tsaAPIServer.GetHandler())
	tsaClient, err := tsaclient.GetTimestampClient(tsaServer.URL)
	must(err, t)
	tsaChain, err := tsaClient.Timestamp.GetTimestampCertChain(nil)
	must(err, t)
	timestampServerURL := tsaServer.URL + "/api/v1/timestamp"
	timestampChainFile := mkfile(tsaChain.Payload, td, t)
	return timestampServerURL, timestampChainFile, tsaServer.Close
}
