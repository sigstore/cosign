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
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
	"testing"
)

func TestGenerateCertificateBundleFiles(t *testing.T) {
	for _, tt := range []struct {
		name            string
		genIntermediate bool
	}{
		{
			name:            "without intermediate",
			genIntermediate: false,
		},
		{
			name:            "with intermediate",
			genIntermediate: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			td := t.TempDir()
			suffix := "foo"
			caCertFile, caPrivKeyFile, caIntermediateCertFile, caIntermediatePrivKeyFile,
				certFile, certChainFile, err := generateCertificateBundleFiles(td, true, suffix)
			if err != nil {
				t.Fatalf("Error generating certificate bundle: %v", err)
			}
			verifyCertificate(t, caCertFile)
			if tt.genIntermediate {
				verifyCertificate(t, caIntermediateCertFile)
			}
			verifyCertificate(t, certFile)

			verifyPrivateKey(t, caPrivKeyFile)
			if tt.genIntermediate {
				verifyPrivateKey(t, caIntermediatePrivKeyFile)
				verifyCertificateChain(t, certChainFile)
			}
		})
	}
}

func verifyCertificate(t *testing.T, certFile string) {
	t.Helper()
	// open and parse certFile, ensure it is a TLS certificate
	data, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("Error reading certificate file %s: %v\n", certFile, err)
		return
	}

	// Check if the file contents are a PEM-encoded TLS certificate
	if !isPEMEncodedCert(data) {
		t.Fatalf("file %s doesn't contain a valid PEM-encoded TLS certificate", certFile)
	}
}

func verifyCertificateChain(t *testing.T, certChainFile string) {
	t.Helper()
	// open and parse certChainFile, ensure it is a TLS certificate chain
	data, err := os.ReadFile(certChainFile)
	if err != nil {
		t.Fatalf("Error reading certificate file %s: %v\n", certChainFile, err)
	}

	// Check if the file contents are a PEM-encoded TLS certificate
	if !isPEMEncodedCertChain(data) {
		t.Fatalf("file %s doesn't contain a valid PEM-encoded TLS certificate chain", certChainFile)
	}
}

// isPEMEncodedCert checks if the provided data is a PEM-encoded certificate
func isPEMEncodedCert(data []byte) bool {
	// Decode the PEM data
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return false
	}

	// Parse the certificate to ensure it is valid
	_, err := x509.ParseCertificate(block.Bytes)
	return err == nil
}

func verifyPrivateKey(t *testing.T, privKeyFile string) {
	t.Helper()
	// open and parse certFile, ensure it is a TLS certificate
	data, err := os.ReadFile(privKeyFile)
	if err != nil {
		t.Fatalf("Error reading private key file %s: %v\n", privKeyFile, err)
		return
	}

	// Check if the file contents are a PEM-encoded private key
	if !isPEMEncodedPrivateKey(data) {
		t.Fatalf("file %s doesn't contain a valid PEM-encoded private key", privKeyFile)
	}
}

// isPEMEncodedPrivateKey checks if the provided data is a PEM-encoded private key
func isPEMEncodedPrivateKey(data []byte) bool {
	// Decode the PEM data
	block, _ := pem.Decode(data)
	if block == nil {
		return false
	}
	var err error

	switch block.Type {
	case "PRIVATE KEY":
		_, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		_, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		_, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return false
	}
	if err != nil {
		log.Printf("isPEMEncodedPrivateKey: %v", err)
		return false
	}

	return true
}

// isPEMEncodedCertChain checks if the provided data is a concatenation of a PEM-encoded
// intermediate certificate followed by a root certificate
func isPEMEncodedCertChain(data []byte) bool {
	// Decode the PEM blocks one by one
	blockCnt := 0
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return false
		}

		// Parse the certificate to ensure it is valid
		_, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return false
		}

		blockCnt++
	}
	// we want exactly two blocks in the certificate chain - intermediate and root
	return blockCnt == 2
}
