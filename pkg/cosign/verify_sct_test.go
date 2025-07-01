// Copyright 2022 The Sigstore Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cosign

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"strings"
	"testing"

	"github.com/google/certificate-transparency-go/testdata"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

var (
	testEmbeddedCertPEM = `-----BEGIN CERTIFICATE-----
MIIDNDCCAtqgAwIBAgIEERggBDAKBggqhkjOPQQDAzArMREwDwYDVQQDEwhzaWdz
dG9yZTEWMBQGA1UEChMNc2lnc3RvcmUubW9jazAeFw0yMzAyMDEwMDAwMDBaFw0y
MzAyMDEwMDEwMDBaMAAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR3rsXlKKGO
bv+Z08sAjs0tyxlzSTKkaFRiy7vjZaFMRQOZ76QKwGFefLkeGwuafSKyLbzhjIgh
OrUzjS+WFAMHo4ICFTCCAhEwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsG
AQUFBwMDMIGlBgNVHREBAf8EgZowgZeGgZRodHRwczovL2dpdGh1Yi5jb20vc2ln
c3RvcmUtY29uZm9ybWFuY2UvZXh0cmVtZWx5LWRhbmdlcm91cy1wdWJsaWMtb2lk
Yy1iZWFjb24vLmdpdGh1Yi93b3JrZmxvd3MvZXh0cmVtZWx5LWRhbmdlcm91cy1v
aWRjLWJlYWNvbi55bWxAcmVmcy9oZWFkcy9tYWluMB0GA1UdDgQWBBTnwHeBmPc9
IrZmBemOaHy4lwv7KDAfBgNVHSMEGDAWgBQ/FFxk7FUxt/oE8lDZEF0s7kasuDA7
BgorBgEEAYO/MAEIBC0MK2h0dHBzOi8vdG9rZW4uYWN0aW9ucy5naXRodWJ1c2Vy
Y29udGVudC5jb20wOQYKKwYBBAGDvzABAQQraHR0cHM6Ly90b2tlbi5hY3Rpb25z
LmdpdGh1YnVzZXJjb250ZW50LmNvbTCBiQYKKwYBBAHWeQIEAgR7BHkAdwB1APcm
yqNBF7qRZUSvNzTpIM1MSS73XOYij9wE7v8vPyfdAAABhgpF7AAAAAQDAEYwRAIg
ORF50hYRIFl2Hgc0vOJfpMjU8gY7BtGfz0oZePlxG4gCIDl6SXQe1+96ENWqM6+5
wxbIUgHL8T3+no43cyuEAe+NMAoGCCqGSM49BAMDA0gAMEUCICqL+qLpRbTPXn6R
i/VId0ejKBNE/B1pm91uOye/COmVAiEAnkRk1n/fPy8cGs6+i+q7bMMl+X2Cm51o
dIrMI9PbjMw=
-----END CERTIFICATE-----`
	testRootCertPEM = `-----BEGIN CERTIFICATE-----
MIIBpzCCAU6gAwIBAgIBATAKBggqhkjOPQQDAzArMREwDwYDVQQDEwhzaWdzdG9y
ZTEWMBQGA1UEChMNc2lnc3RvcmUubW9jazAeFw0yMzAxMDEwMDAwMDBaFw0yNDAx
MDEwMDAwMDBaMCsxETAPBgNVBAMTCHNpZ3N0b3JlMRYwFAYDVQQKEw1zaWdzdG9y
ZS5tb2NrMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYI4heOTrNrZO27elFE8y
nfrdPMikttRkbe+vJKQ50G6bfwQ3WyhLpRwwwohelDAm8xRzJ56nYsIa3VHivVvp
mKNjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYE
FD8UXGTsVTG3+gTyUNkQXSzuRqy4MB8GA1UdIwQYMBaAFD8UXGTsVTG3+gTyUNkQ
XSzuRqy4MAoGCCqGSM49BAMDA0cAMEQCIG0znZffNiOGY6IdlriVJBP1zxx6XWVG
E/omjuhXrRtRAiB0lR8cVoOYtOQcM7X93HWVy0Og4nCfkPK9RXNB68RyZQ==
-----END CERTIFICATE-----`
	testCTLogPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYI4heOTrNrZO27elFE8ynfrdPMik
ttRkbe+vJKQ50G6bfwQ3WyhLpRwwwohelDAm8xRzJ56nYsIa3VHivVvpmA==
-----END PUBLIC KEY-----`
)

func TestContainsSCT(t *testing.T) {
	// test certificate without embedded SCT
	contains, err := ContainsSCT([]byte(testdata.TestCertPEM))
	if err != nil {
		t.Fatalf("unexpected error in ContainsSCT: %v", err)
	}
	if contains {
		t.Fatalf("certificate unexpectedly contained SCT")
	}

	// test certificate with embedded SCT
	contains, err = ContainsSCT([]byte(testEmbeddedCertPEM))
	if err != nil {
		t.Fatalf("unexpected error in ContainsSCT: %v", err)
	}
	if !contains {
		t.Fatalf("certificate unexpectedly did not contain SCT")
	}
}

func TestVerifySCTError(t *testing.T) {
	// verify fails with mismatched verifcation key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("unexpected error generating ECDSA key: %v", err)
	}
	pemKey, err := cryptoutils.MarshalPublicKeyToPEM(key.Public())
	if err != nil {
		t.Fatalf("unexpected error marshalling ECDSA key: %v", err)
	}
	writePubKey(t, string(pemKey))
	// Grab the keys from TUF
	pubKeys, err := GetCTLogPubs(context.Background())
	if err != nil {
		t.Fatalf("Failed to get CTLog public keys from TUF: %v", err)
	}

	err = VerifySCT(context.Background(), []byte(testEmbeddedCertPEM), []byte(testRootCertPEM), []byte{}, pubKeys)
	if err == nil || !strings.Contains(err.Error(), "ctfe public key not found") {
		t.Fatalf("expected error verifying SCT with mismatched key: %v", err)
	}

	// verify fails without either a detached SCT or embedded SCT
	err = VerifySCT(context.Background(), []byte(testdata.TestCertPEM), []byte(testRootCertPEM), []byte{}, pubKeys)
	if err == nil || !strings.Contains(err.Error(), "no SCT found") {
		t.Fatalf("expected error verifying SCT without SCT: %v", err)
	}
}

func TestVerifyEmbeddedSCT(t *testing.T) {
	chain, err := cryptoutils.UnmarshalCertificatesFromPEM([]byte(strings.Join([]string{testEmbeddedCertPEM, testRootCertPEM}, "\n")))
	if err != nil {
		t.Fatalf("error unmarshalling certificate chain: %v", err)
	}

	// Grab the keys from TUF
	pubKeys, err := GetCTLogPubs(context.Background())
	if err != nil {
		t.Fatalf("failed to get CTLog public keys from TUF: %v", err)
	}

	// verify fails without a certificate chain
	err = VerifyEmbeddedSCT(context.Background(), chain[:1], pubKeys)
	if err == nil || err.Error() != "certificate chain must contain at least a certificate and its issuer" {
		t.Fatalf("expected error verifying SCT without chain: %v", err)
	}

	writePubKey(t, testCTLogPublicKeyPEM)
	// Above writes the key to disk and sets up an env variable, so grab the
	// public keys again to get the env path.
	pubKeys, err = GetCTLogPubs(context.Background())
	if err != nil {
		t.Fatalf("failed to get CTLog public keys from TUF: %v", err)
	}

	err = VerifyEmbeddedSCT(context.Background(), chain, pubKeys)
	if err != nil {
		t.Fatalf("unexpected error verifying embedded SCT: %v", err)
	}
}

// writePubKey writes the SCT verification key to disk, since there is not a TUF
// test setup
func writePubKey(t *testing.T, keyPEM string) {
	t.Helper()

	tmpPrivFile, err := os.CreateTemp(t.TempDir(), "cosign_verify_sct_*.key")
	if err != nil {
		t.Fatalf("failed to create temp key file: %v", err)
	}
	t.Cleanup(func() { tmpPrivFile.Close() })
	if _, err := tmpPrivFile.Write([]byte(keyPEM)); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}
	os.Setenv("SIGSTORE_CT_LOG_PUBLIC_KEY_FILE", tmpPrivFile.Name())
	t.Cleanup(func() { os.Unsetenv("SIGSTORE_CT_LOG_PUBLIC_KEY_FILE") })
}
