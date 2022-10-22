// Copyright 2022 The Sigstore Authors.
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

package ctl

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/testdata"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
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
	contains, err = ContainsSCT([]byte(testdata.TestEmbeddedCertPEM))
	if err != nil {
		t.Fatalf("unexpected error in ContainsSCT: %v", err)
	}
	if !contains {
		t.Fatalf("certificate unexpectedly did not contain SCT")
	}
}

// From https://github.com/google/certificate-transparency-go/blob/e76f3f637053b90c8168d29b01ca162cd235ace5/ctutil/ctutil_test.go
func TestVerifySCT(t *testing.T) {
	tests := []struct {
		desc     string
		certPEM  string
		chainPEM string
		sct      []byte
		embedded bool
		wantErr  bool
		errMsg   string
	}{
		{
			desc:     "cert",
			certPEM:  testdata.TestCertPEM,
			chainPEM: testdata.CACertPEM,
			sct:      testdata.TestCertProof,
		},
		{
			desc:     "invalid SCT",
			certPEM:  testdata.TestPreCertPEM,
			chainPEM: testdata.CACertPEM,
			sct:      testdata.TestCertProof,
			wantErr:  true,
		},
		{
			desc:     "cert with embedded SCT",
			certPEM:  testdata.TestEmbeddedCertPEM,
			chainPEM: testdata.CACertPEM,
			sct:      testdata.TestPreCertProof,
			embedded: true,
		},
		{
			desc:     "cert with invalid embedded SCT",
			certPEM:  testdata.TestInvalidEmbeddedCertPEM,
			chainPEM: testdata.CACertPEM,
			sct:      testdata.TestInvalidProof,
			embedded: true,
			wantErr:  true,
			errMsg:   "failed to verify ECDSA signature",
		},
	}

	writePubKey(t, testdata.LogPublicKeyPEM)

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			// convert SCT to response struct if detached
			var sctBytes []byte
			if !test.embedded {
				var sct ct.SignedCertificateTimestamp
				if _, err := tls.Unmarshal(test.sct, &sct); err != nil {
					t.Fatalf("error tls-unmarshalling sct: %s", err)
				}
				chainResp, err := toAddChainResponse(&sct)
				if err != nil {
					t.Fatalf("error generating chain response: %v", err)
				}
				sctBytes, err = json.Marshal(chainResp)
				if err != nil {
					t.Fatalf("error marshalling chain: %v", err)
				}
			}

			err := VerifySCT(context.Background(), []byte(test.certPEM), []byte(test.chainPEM), sctBytes)
			if gotErr := err != nil; gotErr != test.wantErr && !strings.Contains(err.Error(), test.errMsg) {
				t.Errorf("VerifySCT(_,_,_, %t) = %v, want error? %t", test.embedded, err, test.wantErr)
			}
		})
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
	err = VerifySCT(context.Background(), []byte(testdata.TestEmbeddedCertPEM), []byte(testdata.CACertPEM), []byte{})
	if err == nil || !strings.Contains(err.Error(), "ctfe public key not found") {
		t.Fatalf("expected error verifying SCT with mismatched key: %v", err)
	}

	// verify fails without either a detached SCT or embedded SCT
	err = VerifySCT(context.Background(), []byte(testdata.TestCertPEM), []byte(testdata.CACertPEM), []byte{})
	if err == nil || !strings.Contains(err.Error(), "no SCT found") {
		t.Fatalf("expected error verifying SCT without SCT: %v", err)
	}
}

func TestVerifyEmbeddedSCT(t *testing.T) {
	chain, err := cryptoutils.UnmarshalCertificatesFromPEM([]byte(testdata.TestEmbeddedCertPEM + testdata.CACertPEM))
	if err != nil {
		t.Fatalf("error unmarshalling certificate chain: %v", err)
	}

	// verify fails without a certificate chain
	err = VerifyEmbeddedSCT(context.Background(), chain[:1])
	if err == nil || err.Error() != "certificate chain must contain at least a certificate and its issuer" {
		t.Fatalf("expected error verifying SCT without chain: %v", err)
	}

	writePubKey(t, testdata.LogPublicKeyPEM)
	err = VerifyEmbeddedSCT(context.Background(), chain)
	if err != nil {
		t.Fatalf("unexpected error verifying embedded SCT: %v", err)
	}
}

// toAddChainResponse converts an SCT to a response struct, the expected structure for detached SCTs
func toAddChainResponse(sct *ct.SignedCertificateTimestamp) (*ct.AddChainResponse, error) {
	sig, err := tls.Marshal(sct.Signature)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signature: %w", err)
	}
	addChainResp := &ct.AddChainResponse{
		SCTVersion: sct.SCTVersion,
		Timestamp:  sct.Timestamp,
		Extensions: base64.StdEncoding.EncodeToString(sct.Extensions),
		ID:         sct.LogID.KeyID[:],
		Signature:  sig,
	}

	return addChainResp, nil
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
