// Copyright 2025 The Sigstore Authors.
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

package bundle

import (
	"bytes"
	"context"
	"crypto/x509"
	"testing"

	"github.com/sigstore/cosign/v3/internal/test"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func TestLocalCertChainProvider_GetCertificateChain(t *testing.T) {
	rootCert, rootKey, err := test.GenerateRootCa()
	if err != nil {
		t.Fatalf("GenerateRootCa: %v", err)
	}
	subCert, subKey, err := test.GenerateSubordinateCa(rootCert, rootKey)
	if err != nil {
		t.Fatalf("GenerateSubordinateCa: %v", err)
	}
	leafCert, _, err := test.GenerateLeafCert("subject@mail.com", "oidc-issuer", subCert, subKey)
	if err != nil {
		t.Fatalf("GenerateLeafCert: %v", err)
	}

	leafPEM, err := cryptoutils.MarshalCertificateToPEM(leafCert)
	if err != nil {
		t.Fatalf("MarshalCertificateToPEM: %v", err)
	}
	rootPEM, err := cryptoutils.MarshalCertificateToPEM(rootCert)
	if err != nil {
		t.Fatalf("MarshalCertificateToPEM: %v", err)
	}
	subAndRootPEM, err := cryptoutils.MarshalCertificatesToPEM([]*x509.Certificate{subCert, rootCert})
	if err != nil {
		t.Fatalf("MarshalCertificatesToPEM: %v", err)
	}
	leafSubAndRootPEM, err := cryptoutils.MarshalCertificatesToPEM([]*x509.Certificate{leafCert, subCert, rootCert})
	if err != nil {
		t.Fatalf("MarshalCertificatesToPEM: %v", err)
	}

	testCases := []struct {
		name      string
		cert      []byte
		chain     []byte
		wantDER   [][]byte
		wantError bool
	}{
		{
			name:    "leaf with root-only chain",
			cert:    leafPEM,
			chain:   rootPEM,
			wantDER: [][]byte{leafCert.Raw, rootCert.Raw},
		},
		{
			name:    "leaf with sub and root chain",
			cert:    leafPEM,
			chain:   subAndRootPEM,
			wantDER: [][]byte{leafCert.Raw, subCert.Raw, rootCert.Raw},
		},
		{
			name:    "leaf already present in chain is deduped",
			cert:    leafPEM,
			chain:   leafSubAndRootPEM,
			wantDER: [][]byte{leafCert.Raw, subCert.Raw, rootCert.Raw},
		},
		{
			name:      "invalid leaf PEM",
			cert:      []byte("not a pem"),
			chain:     rootPEM,
			wantError: true,
		},
		{
			name:      "invalid chain PEM",
			cert:      leafPEM,
			chain:     []byte("not a pem"),
			wantError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider := &localCertChainProvider{cert: tc.cert, chain: tc.chain}
			got, err := provider.GetCertificateChain(context.Background(), nil, nil)
			if tc.wantError {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tc.wantDER) {
				t.Fatalf("expected %d certs, got %d", len(tc.wantDER), len(got))
			}
			for i := range got {
				if !bytes.Equal(got[i], tc.wantDER[i]) {
					t.Errorf("cert at index %d does not match expected DER", i)
				}
			}
		})
	}
}
