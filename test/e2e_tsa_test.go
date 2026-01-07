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
	"fmt"
	"io/ioutil"
	"net/http/httptest"
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
	"github.com/sigstore/sigstore-go/pkg/root"
	tsaclient "github.com/sigstore/timestamp-authority/v2/pkg/client"
	tsaserver "github.com/sigstore/timestamp-authority/v2/pkg/server"
	"github.com/spf13/viper"
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
	bundlePath := filepath.Join(td, "cosign.bundle")

	_, privKey, pubKey := keypair(t, td)

	// Set up TSA server with TLS
	timestampCACert, timestampServerCert, timestampServerKey, _, _ := generateMTLSKeys(t, td)
	timestampServerURL, timestampChainFile, tsaCleanup := setUpTSAServerWithTLS(t, td, timestampCACert, timestampServerKey, timestampServerCert)
	t.Cleanup(tsaCleanup)

	trustedMaterial, err := buildTsaTrustedMaterial(timestampCACert, timestampServerCert, timestampChainFile, timestampServerURL)
	if err != nil {
		t.Fatalf("failed building TSA trusted material: %v", err)
	}

	signingKO := options.KeyOpts{
		KeyRef:               privKey,
		PassFunc:             passFunc,
		BundlePath:           bundlePath,
		TrustedMaterial:      trustedMaterial,
	}
	_, err = sign.SignBlobCmd(t.Context(), ro, signingKO, blobPath, "", "", true, "", "", false)
	must(err, t)

	verifyKO := options.KeyOpts{
		KeyRef:               pubKey,
		BundlePath:           bundlePath,
	}

	verifyCmd := cliverify.VerifyBlobCmd{
		KeyOpts: verifyKO,
		IgnoreTlog: true,
	}
	must(verifyCmd.Exec(context.Background(), blobPath), t)
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

func buildTsaTrustedMaterial(caPath, serverCertPath, chainPath, tsaURI string) (root.TrustedMaterial, error) {
    readCertsFromPEM := func(path string) ([]*x509.Certificate, error) {
        b, err := ioutil.ReadFile(path)
        if err != nil {
            return nil, err
        }
        var certs []*x509.Certificate
        for {
            var block *pem.Block
            block, b = pem.Decode(b)
            if block == nil {
                break
            }
            if block.Type != "CERTIFICATE" {
                continue
            }
            c, err := x509.ParseCertificate(block.Bytes)
            if err != nil {
                return nil, err
            }
            certs = append(certs, c)
        }
        if len(certs) == 0 {
            return nil, fmt.Errorf("no certificates found in %s", path)
        }
        return certs, nil
    }

    var leaf *x509.Certificate
    var intermediates []*x509.Certificate
    var rootCert *x509.Certificate

    if chainPath != "" {
        certs, err := readCertsFromPEM(chainPath)
        if err != nil {
            return nil, fmt.Errorf("reading chain file: %w", err)
        }
        chainLen := len(certs)
        if chainLen < 1 {
            return nil, fmt.Errorf("chain file %s contains no certs", chainPath)
        }
        for i, c := range certs {
            switch {
            case i == 0 && !c.IsCA:
                leaf = c
            case i < chainLen-1:
                intermediates = append(intermediates, c)
            case i == chainLen-1:
                rootCert = c
            }
        }
        if leaf == nil && len(certs) >= 1 && !certs[0].IsCA {
            leaf = certs[0]
        }
    }

    if rootCert == nil && caPath != "" {
        certs, err := readCertsFromPEM(caPath)
        if err != nil {
            return nil, fmt.Errorf("reading CA file: %w", err)
        }
        rootCert = certs[0]
    }
    if leaf == nil && serverCertPath != "" {
        certs, err := readCertsFromPEM(serverCertPath)
        if err != nil {
            return nil, fmt.Errorf("reading server cert file: %w", err)
        }
        leaf = certs[0]
    }

    if rootCert == nil {
        return nil, fmt.Errorf("no root certificate available")
    }
    if leaf == nil {
        return nil, fmt.Errorf("no leaf (server) certificate available")
    }

    tsa := &root.SigstoreTimestampingAuthority{
        Root:          rootCert,
        Intermediates: intermediates,
        Leaf:          leaf,
        URI:           tsaURI,
        ValidityPeriodStart: leaf.NotBefore,
        ValidityPeriodEnd:   leaf.NotAfter,
    }

    tm := root.TrustedMaterialCollection{
        &tsaMaterial{tsas: []root.TimestampingAuthority{tsa}},
    }
    return tm, nil
}

type tsaMaterial struct {
		root.BaseTrustedMaterial
		tsas []root.TimestampingAuthority
}
func (t *tsaMaterial) TimestampingAuthorities() []root.TimestampingAuthority {
		return t.tsas
}
