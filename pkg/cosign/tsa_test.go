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
	"errors"
	"os"
	"testing"

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

func MockGetTufTargets(name string) ([]byte, error) {
	switch name {
	case `tsa_leaf.crt.pem`:
		return []byte(testLeafCert), nil
	case `tsa_root.crt.pem`:
		return []byte(testRootCert), nil
	default:
		return nil, errors.New("no intermediates")
	}
}

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
	require.NotNil(t, tsaCerts.LeafCert)
	require.NotNil(t, tsaCerts.RootCert)
	require.Len(t, tsaCerts.RootCert, 1)
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
	require.NotNil(t, tsaCerts.LeafCert)
	require.NotNil(t, tsaCerts.RootCert)
	require.Len(t, tsaCerts.RootCert, 1)
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
	require.NotNil(t, tsaCerts.LeafCert)
	require.NotNil(t, tsaCerts.RootCert)
	require.Len(t, tsaCerts.RootCert, 1)
}
