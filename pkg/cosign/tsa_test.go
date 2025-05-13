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

package cosign

import (
	"context"
	"encoding/pem"
	"os"
	"testing"

	"github.com/sigstore/cosign/v2/test"
	"github.com/sigstore/sigstore/pkg/tuf"
	"github.com/stretchr/testify/require"
)

const (
	testLeafCert = `-----BEGIN CERTIFICATE-----
MIIBjzCCATSgAwIBAgIRAOoa5khdNMW26Nz0VCvjbBAwCgYIKoZIzj0EAwIwGzEZ
MBcGA1UEAxMQaHR0cHM6Ly9ibGFoLmNvbTAgFw0yNDA2MDMyMDE2MDFaGA8yMTI0
MDUxMDIwMTYwMFowGzEZMBcGA1UEAxMQaHR0cHM6Ly9ibGFoLmNvbTBZMBMGByqG
SM49AgEGCCqGSM49AwEHA0IABL7w/TW5lOU9KwnGQRIyZp/ReNQF1eA2rKC582Jo
nMomwCk2bA8c5dHrvvHe+mI8JeMNEg3lkIsVQp46dKGlgYujVzBVMA4GA1UdDwEB
/wQEAwIBBjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBSA7lVsQm5OUzvYi+o8PuBs
CrAnljAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAKBggqhkjOPQQDAgNJADBGAiEA
oJSZgJPX2tqXhfvLm+5UR399+E6+rgUnSRUf4+p+K5gCIQCmtfuv8IkUIYE5ybtx
+bn5E95xINfDMSPBa+0PEbB5RA==
-----END CERTIFICATE-----`
	testRootCert = `-----BEGIN CERTIFICATE-----
MIIBezCCASKgAwIBAgIRAMvdlXw/uuYvsJaCTa02uW4wCgYIKoZIzj0EAwIwGzEZ
MBcGA1UEAxMQaHR0cHM6Ly9ibGFoLmNvbTAgFw0yNDA2MDMyMDE1NTFaGA8yMTI0
MDUxMDIwMTU1MFowGzEZMBcGA1UEAxMQaHR0cHM6Ly9ibGFoLmNvbTBZMBMGByqG
SM49AgEGCCqGSM49AwEHA0IABLziRBPdWUTx9x3Z7zIMyo/C9cqsLK+hqnWDQS7K
TA38mZhMHnJ0vSaEA4g9J2ccI1x4G/HegCi9LkJG/EZLBjyjRTBDMA4GA1UdDwEB
/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEBMB0GA1UdDgQWBBQuDQqo97s/5Lc5
IxmFcVg3arCV2DAKBggqhkjOPQQDAgNHADBEAiAJOr0GnYaqVxShSEgVJKi/hYXf
PH5bKk0M9ceasS7VwQIgMkxzlWr+m10OELtAbOlI8faN/5WFKm8m8rrwnhmHzjw=
-----END CERTIFICATE-----`
)

func TestGetTSACertsFromEnv(t *testing.T) {
	tempFile, err := os.CreateTemp("", "tsa_cert_chain.pem")
	require.NoError(t, err)
	defer os.Remove(tempFile.Name())

	_, err = tempFile.Write([]byte(testLeafCert + "\n" + testRootCert))
	require.NoError(t, err)

	os.Setenv("SIGSTORE_TSA_CERTIFICATE_FILE", tempFile.Name())
	defer os.Unsetenv("SIGSTORE_TSA_CERTIFICATE_FILE")

	tsaCerts, err := GetTSACerts(context.Background(), tempFile.Name(), GetTufTargets)
	if err != nil {
		t.Fatalf("Failed to get TSA certs from env: %v", err)
	}
	require.NotNil(t, tsaCerts)
	require.Len(t, tsaCerts, 1)
	require.NotNil(t, tsaCerts[0].LeafCert)
	require.NotNil(t, tsaCerts[0].RootCert)
	require.Len(t, tsaCerts[0].RootCert, 1)
}

func TestGetTSACertsFromPath(t *testing.T) {
	tempFile, err := os.CreateTemp("", "tsa_cert_chain_path.pem")
	require.NoError(t, err)
	defer os.Remove(tempFile.Name())

	_, err = tempFile.Write([]byte(testLeafCert + "\n" + testRootCert))
	require.NoError(t, err)

	tsaCerts, err := GetTSACerts(context.Background(), tempFile.Name(), GetTufTargets)
	if err != nil {
		t.Fatalf("Failed to get TSA certs from path: %v", err)
	}
	require.NotNil(t, tsaCerts)
	require.Len(t, tsaCerts, 1)
	require.NotNil(t, tsaCerts[0].LeafCert)
	require.NotNil(t, tsaCerts[0].RootCert)
	require.Len(t, tsaCerts[0].RootCert, 1)
}

func TestGetTSACertsFromTUF(t *testing.T) {
	originalValue := os.Getenv("SIGSTORE_TSA_CERTIFICATE_FILE")
	os.Unsetenv("SIGSTORE_TSA_CERTIFICATE_FILE")
	defer os.Setenv("SIGSTORE_TSA_CERTIFICATE_FILE", originalValue)

	tempFile, err := os.CreateTemp("", "tsa_cert_chain.pem")
	require.NoError(t, err)
	defer os.Remove(tempFile.Name())

	_, err = tempFile.Write([]byte(testLeafCert + "\n" + testRootCert))
	require.NoError(t, err)

	tsaCerts, err := GetTSACerts(context.Background(), tempFile.Name(), GetTufTargets)
	if err != nil {
		t.Fatalf("Failed to get TSA certs from TUF: %v", err)
	}
	require.NotNil(t, tsaCerts)
	require.Len(t, tsaCerts, 1)
	require.NotNil(t, tsaCerts[0].LeafCert)
	require.NotNil(t, tsaCerts[0].RootCert)
	require.Len(t, tsaCerts[0].RootCert, 1)
}

func TestGetMultipleTSACertsFromTUF(t *testing.T) {
	originalValue := os.Getenv("SIGSTORE_TSA_CERTIFICATE_FILE")
	os.Unsetenv("SIGSTORE_TSA_CERTIFICATE_FILE")
	defer os.Setenv("SIGSTORE_TSA_CERTIFICATE_FILE", originalValue)

	// generate random certificates
	rootCert0, rootKey0, _ := test.GenerateRootCa()
	leafCert0, _, _ := test.GenerateLeafCert("subject", "oidc-issuer", rootCert0, rootKey0)
	leafPEM0 := pem.EncodeToMemory(&pem.Block{Type: "Certificate", Bytes: leafCert0.Raw})
	rootPEM0 := pem.EncodeToMemory(&pem.Block{Type: "Certificate", Bytes: rootCert0.Raw})
	rootCert1, rootKey1, _ := test.GenerateRootCa()
	leafCert1, _, _ := test.GenerateLeafCert("subject", "oidc-issuer", rootCert1, rootKey1)
	leafPEM1 := pem.EncodeToMemory(&pem.Block{Type: "Certificate", Bytes: leafCert1.Raw})
	rootPEM1 := pem.EncodeToMemory(&pem.Block{Type: "Certificate", Bytes: rootCert1.Raw})

	mockGetTufTargets := func(_ context.Context, _ tuf.UsageKind, _ []string) ([][]byte, error) {
		return [][]byte{
			[]byte(string(leafPEM0) + "\n" + string(rootPEM0)),
			[]byte(string(leafPEM1) + "\n" + string(rootPEM1)),
		}, nil
	}

	tsaCerts, err := GetTSACerts(context.Background(), "", mockGetTufTargets)
	if err != nil {
		t.Fatalf("Failed to get TSA certs from TUF: %v", err)
	}
	require.NotNil(t, tsaCerts)
	require.Len(t, tsaCerts, 2)
	require.Equal(t, leafCert0, tsaCerts[0].LeafCert)
	require.Equal(t, rootCert0, tsaCerts[0].RootCert[0])
	require.Equal(t, leafCert1, tsaCerts[1].LeafCert)
	require.Equal(t, rootCert1, tsaCerts[1].RootCert[0])
}
