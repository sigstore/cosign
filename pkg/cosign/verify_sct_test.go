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

//go:build sct
// +build sct

package cosign

import (
	"crypto/x509"
	"os"
	"testing"

	"github.com/google/certificate-transparency-go/testdata"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// TODO: Move back into verify_test.go once the test cert has been regenerated
func TestValidateAndUnpackCertWithSCT(t *testing.T) {
	chain, err := cryptoutils.UnmarshalCertificatesFromPEM([]byte(testdata.TestEmbeddedCertPEM + testdata.CACertPEM))
	if err != nil {
		t.Fatalf("error unmarshalling certificate chain: %v", err)
	}

	rootPool := x509.NewCertPool()
	rootPool.AddCert(chain[1])
	co := &CheckOpts{
		RootCerts: rootPool,
		// explicitly set to false
		IgnoreSCT: false,
	}

	// write SCT verification key to disk
	tmpPrivFile, err := os.CreateTemp(t.TempDir(), "cosign_verify_sct_*.key")
	if err != nil {
		t.Fatalf("failed to create temp key file: %v", err)
	}
	defer tmpPrivFile.Close()
	if _, err := tmpPrivFile.Write([]byte(testdata.LogPublicKeyPEM)); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}
	t.Setenv("SIGSTORE_CT_LOG_PUBLIC_KEY_FILE", tmpPrivFile.Name())

	_, err = ValidateAndUnpackCert(chain[0], co)
	if err != nil {
		t.Errorf("ValidateAndUnpackCert expected no error, got err = %v", err)
	}

	// validate again, explicitly setting enforce SCT
	_, err = ValidateAndUnpackCert(chain[0], co)
	if err != nil {
		t.Errorf("ValidateAndUnpackCert expected no error, got err = %v", err)
	}
}
