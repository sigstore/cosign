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

package tsa

import (
	"crypto/x509"
	"reflect"
	"testing"

	"github.com/sigstore/cosign/test"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func TestSplitPEMCertificateChain(t *testing.T) {
	rootCert, rootKey, _ := test.GenerateRootCa()
	subCert, subKey, _ := test.GenerateSubordinateCa(rootCert, rootKey)
	leafCert, _, _ := test.GenerateLeafCert("subject", "oidc-issuer", subCert, subKey)
	rootCert2, rootKey2, _ := test.GenerateRootCa()
	subCert2, subKey2, _ := test.GenerateSubordinateCa(rootCert2, rootKey2)
	leafCert2, _, _ := test.GenerateLeafCert("subject", "oidc-issuer", subCert2, subKey2)
	expectedLeaves := []*x509.Certificate{leafCert, leafCert2}
	expectedInts := []*x509.Certificate{subCert, subCert2}
	expectedRoots := []*x509.Certificate{rootCert, rootCert2}

	pem, err := cryptoutils.MarshalCertificatesToPEM([]*x509.Certificate{rootCert, subCert, leafCert, rootCert2, subCert2, leafCert2})
	if err != nil {
		t.Fatalf("unexpected error marshalling certificates to PEM: %v", err)
	}

	leaves, intermediates, roots, err := SplitPEMCertificateChain(pem)
	if err != nil {
		t.Fatalf("unexpected error splitting certificates from PEM: %v", err)
	}
	if !reflect.DeepEqual(leaves, expectedLeaves) {
		t.Fatal("leaf certificates were not equal")
	}
	if !reflect.DeepEqual(intermediates, expectedInts) {
		t.Fatal("intermediates were not equal")
	}
	if !reflect.DeepEqual(roots, expectedRoots) {
		t.Fatal("roots were not equal")
	}
}
