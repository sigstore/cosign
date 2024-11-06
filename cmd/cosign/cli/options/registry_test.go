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

package options

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

func generatePrivateKey(t *testing.T) *rsa.PrivateKey {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	return privateKey
}

func writePrivateKey(t *testing.T, privateKey *rsa.PrivateKey, fileLocation string) {
	// Encode the private key to PEM format
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Write the private key to the specified file
	err := os.WriteFile(fileLocation, privateKeyPEM, 0600)
	if err != nil {
		t.Fatal(err)
	}
}

func generateCertificate(t *testing.T, dir string, isCa bool) (certficateLocation, privateKeyLocation string) {
	certficateLocation = createTempFile(t, dir)
	privateKeyLocation = createTempFile(t, dir)

	// Generate a private key for the CA
	privateKey := generatePrivateKey(t)

	// Create a self-signed certificate for the CA
	caTemplate := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now().Add(time.Hour * -24),
		NotAfter:              time.Now().Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  isCa,
		SerialNumber:          big.NewInt(1337),
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	// Encode the CA certificate to PEM format
	caCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertDER,
	})

	// Write the CA certificate to the specified file
	err = os.WriteFile(certficateLocation, caCertPEM, 0644)
	if err != nil {
		t.Fatal(err)
	}

	writePrivateKey(t, privateKey, privateKeyLocation)

	return certficateLocation, privateKeyLocation
}

func TestGetTLSConfig(t *testing.T) {
	tempDir := t.TempDir() // Create a temporary directory for testing
	t.Cleanup(func() {
		os.RemoveAll(tempDir)
	})
	validCaCertificate, validCaKey := generateCertificate(t, tempDir, true)
	validClientCertificate, validClientKey := generateCertificate(t, tempDir, false)

	tests := []struct {
		name               string
		registryCACert     string
		registryClientCert string
		registryClientKey  string
		registryServerName string
		allowInsecure      bool
		expectError        string
	}{
		{
			name:               "Valid CA Cert, Client Cert and Key, Server Name, Allow Insecure",
			registryCACert:     validCaCertificate,
			registryClientCert: validClientCertificate,
			registryClientKey:  validClientKey,
			registryServerName: "example.com",
			allowInsecure:      true,
		},
		{
			name:               "Wrong key for client cert",
			registryCACert:     validCaCertificate,
			registryClientCert: validClientCertificate,
			registryClientKey:  validCaKey, // using ca key for client cert must fail
			registryServerName: "example.com",
			allowInsecure:      true,
			expectError:        fmt.Sprintf("unable to read client certs from cert %s, key %s: tls: private key does not match public key", validClientCertificate, validCaKey),
		},
		{
			name:               "Wrong ca key",
			registryCACert:     validClientKey, // using client key for ca cert must fail
			registryClientCert: validClientCertificate,
			registryClientKey:  validClientKey,
			registryServerName: "example.com",
			allowInsecure:      true,
			expectError:        fmt.Sprintf("no valid CA certs found in %s", validClientKey),
		},
		{
			name:               "Invalid CA path",
			registryCACert:     "/not/existing/path/fooobar", // this path is not expected to exist
			registryClientCert: validClientCertificate,
			registryClientKey:  validClientKey,
			registryServerName: "example.com",
			allowInsecure:      true,
			expectError:        "open /not/existing/path/fooobar: ", // the error message is OS dependent
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &RegistryOptions{
				RegistryCACert:     tt.registryCACert,
				RegistryClientCert: tt.registryClientCert,
				RegistryClientKey:  tt.registryClientKey,
				RegistryServerName: tt.registryServerName,
				AllowInsecure:      tt.allowInsecure,
			}

			tlsConfig, err := o.getTLSConfig()
			if tt.expectError != "" {
				if err == nil || !strings.HasPrefix(err.Error(), tt.expectError) {
					t.Errorf("getTLSConfig()\nerror: \"%v\",\nexpectError: \"%v\"", err, tt.expectError)
					return
				}
			} else {
				if err != nil {
					t.Errorf("getTLSConfig() error = %v, expectError %v", err, tt.expectError)
					return
				}
			}

			if err == nil {
				if tt.registryCACert != "" {
					if tlsConfig.RootCAs == nil {
						t.Errorf("Expected RootCAs to be set")
					}
				}

				if tt.registryClientCert != "" && tt.registryClientKey != "" {
					if len(tlsConfig.Certificates) == 0 {
						t.Errorf("Expected Certificates to be set")
					}
				}

				if tt.registryServerName != "" {
					if tlsConfig.ServerName != tt.registryServerName {
						t.Errorf("Expected ServerName to be %s, got %s", tt.registryServerName, tlsConfig.ServerName)
					}
				}

				if tt.allowInsecure {
					if !tlsConfig.InsecureSkipVerify {
						t.Errorf("Expected InsecureSkipVerify to be true")
					}
				}
			}
		})
	}
}

// Helper function to create temporary files for testing
func createTempFile(t *testing.T, dir string) string {
	tmpfile, err := os.CreateTemp(dir, "registry-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer tmpfile.Close()

	return tmpfile.Name()
}
