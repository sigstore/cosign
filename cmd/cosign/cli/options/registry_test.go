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

func generateCertificate(t *testing.T, isCa bool) (certficateLocation, privateKeyLocation string) {
	certficateLocation = createTempFile(t)
	privateKeyLocation = createTempFile(t)

	// Generate a private key for the CA
	privateKey := generatePrivateKey(t)

	// Create a self-signed certificate for the CA
	caTemplate := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now().Add(time.Hour*-24),
		NotAfter:              time.Now().Add(time.Hour*24),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  isCa,
		SerialNumber: big.NewInt(1337),
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
	validCaCertificate, validCaKey := generateCertificate(t, true)
	validClientCertificate, validClientKey := generateCertificate(t, false)

	t.Cleanup(func() {
		removeTempFile(t, validCaCertificate)
		removeTempFile(t, validCaKey)
		removeTempFile(t, validClientCertificate)
		removeTempFile(t, validClientKey)
	})

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
			name: "Wrong key for client cert",
			registryCACert: validCaCertificate,
			registryClientCert: validClientCertificate,
			registryClientKey: validCaKey, // using ca key for client cert must fail
			registryServerName: "example.com",
			allowInsecure: true,
			expectError: fmt.Sprintf("unable to read client certs from cert %s, key %s: tls: private key does not match public key", validClientCertificate, validCaKey),
		},
		{
			name: "Wrong ca key",
			registryCACert: validClientKey, // using client key for ca cert must fail
			registryClientCert: validClientCertificate,
			registryClientKey: validClientKey,
			registryServerName: "example.com",
			allowInsecure: true,
			expectError: fmt.Sprintf("no valid CA certs found in %s", validClientKey),
		},
		{
			name: "Invalid CA path",
			registryCACert: "/not/existing/path/fooobar", // this path is not expected to exist
			registryClientCert: validClientCertificate,
			registryClientKey: validClientKey,
			registryServerName: "example.com",
			allowInsecure: true,
			expectError: fmt.Sprintf("open /not/existing/path/fooobar: no such file or directory"),
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
				if err == nil || err.Error() != tt.expectError {
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
func createTempFile(t *testing.T) string {
	tmpfile, err := os.CreateTemp("", "registry-test-")
	if err != nil {
		t.Fatal(err)
	}

	return tmpfile.Name()
}

// Helper function to remove temporary files after testing
func removeTempFile(t *testing.T, filename string) {
	if err := os.Remove(filename); err != nil {
		t.Fatal(err)
	}
}
