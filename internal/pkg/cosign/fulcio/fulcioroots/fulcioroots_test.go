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

package fulcioroots

import (
	"os"
	"sync"
	"testing"

	"github.com/sigstore/cosign/test"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func resetState() {
	rootsOnce = sync.Once{}
}

func TestGetFulcioRoots(t *testing.T) {
	t.Cleanup(resetState)
	rootCert, rootPriv, _ := test.GenerateRootCa()
	rootPemCert, _ := cryptoutils.MarshalCertificateToPEM(rootCert)
	subCert, _, _ := test.GenerateSubordinateCa(rootCert, rootPriv)
	subPemCert, _ := cryptoutils.MarshalCertificateToPEM(subCert)

	var chain []byte
	chain = append(chain, subPemCert...)
	chain = append(chain, rootPemCert...)

	tmpCertFile, err := os.CreateTemp(t.TempDir(), "cosign_fulcio_root_*.cert")
	if err != nil {
		t.Fatalf("failed to create temp cert file: %v", err)
	}
	defer tmpCertFile.Close()
	if _, err := tmpCertFile.Write(chain); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}
	t.Setenv("SIGSTORE_ROOT_FILE", tmpCertFile.Name())

	if rootCertPool, err := Get(); err != nil {
		t.Fatalf("failed to get roots: %v", err)
	} else if len(rootCertPool.Subjects()) != 1 { // nolint:staticcheck
		// ignore deprecation error because certificates do not contain from SystemCertPool
		t.Errorf("expected 1 root certificate, got 0")
	}

	if subCertPool, err := GetIntermediates(); err != nil {
		t.Fatalf("failed to get intermediates: %v", err)
	} else if len(subCertPool.Subjects()) != 1 { // nolint:staticcheck
		// ignore deprecation error because certificates do not contain from SystemCertPool
		t.Errorf("expected 1 intermediate certificate, got 0")
	}
}

func TestGetFulcioRootsWithoutIntermediate(t *testing.T) {
	t.Cleanup(resetState)
	rootCert, _, _ := test.GenerateRootCa()
	rootPemCert, _ := cryptoutils.MarshalCertificateToPEM(rootCert)

	tmpCertFile, err := os.CreateTemp(t.TempDir(), "cosign_fulcio_root_*.cert")
	if err != nil {
		t.Fatalf("failed to create temp cert file: %v", err)
	}
	defer tmpCertFile.Close()
	if _, err := tmpCertFile.Write(rootPemCert); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}
	t.Setenv("SIGSTORE_ROOT_FILE", tmpCertFile.Name())

	if rootCertPool, err := Get(); err != nil {
		t.Fatalf("failed to get roots: %v", err)
	} else if len(rootCertPool.Subjects()) != 1 { // nolint:staticcheck
		// ignore deprecation error because certificates do not contain from SystemCertPool
		t.Errorf("expected 1 root certificate, got 0")
	}

	if subCertPool, err := GetIntermediates(); err != nil {
		t.Fatalf("failed to get intermediates: %v", err)
	} else if subCertPool != nil {
		t.Errorf("expected no intermediate cert pool")
	}
}
