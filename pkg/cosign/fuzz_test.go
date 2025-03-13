//
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
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/sigstore/cosign/v2/pkg/oci/mutate"
)

var (
	defaultFuzzRef = "fuzz/test"
)

func fuzzPass(s string) PassFunc {
	return func(_ bool) ([]byte, error) {
		return []byte(s), nil
	}
}

func FuzzImportKeyPairLoadPrivateKey(f *testing.F) {
	f.Add([]byte(validrsa), []byte("password"))
	f.Add([]byte(validrsapkcs1), []byte("password"))
	f.Add([]byte(validrsapkcs8), []byte("password"))
	f.Add([]byte(validecp256), []byte("password"))
	f.Add([]byte(validecp384), []byte("password"))
	f.Add([]byte(validecp521), []byte("password"))
	f.Add([]byte(validecpkcs8), []byte("password"))
	f.Add([]byte(ed25519key), []byte("password"))
	f.Add([]byte(pemcosignkey), []byte("password"))
	f.Add([]byte(pemcosigneckey), []byte("password"))
	f.Add([]byte(pemsigstorekey), []byte("password"))
	f.Fuzz(func(t *testing.T, pemData, password []byte) {
		path := t.TempDir()
		keyFilePath := filepath.Join(path, "fuzzKey")
		err := os.WriteFile(keyFilePath, pemData, 0x755)
		if err != nil {
			return
		}
		keyBytes, err := ImportKeyPair(keyFilePath, fuzzPass(string(password)))
		if err != nil {
			return
		}
		// Loading the private key should also work.
		_, err = LoadPrivateKey(keyBytes.PrivateBytes, password, nil)
		if err != nil {
			t.Fatal(err)
		}
	})
}

func FuzzSigVerify(f *testing.F) {
	f.Fuzz(func(t *testing.T, sigData, payloadData []byte, verificationTest int) {
		path := t.TempDir()
		sigPath := filepath.Join(path, "sigFile")
		err := os.WriteFile(sigPath, sigData, 0x755)
		if err != nil {
			return
		}
		payloadPath := filepath.Join(path, "payloadFile")
		err = os.WriteFile(payloadPath, payloadData, 0x755)
		if err != nil {
			return
		}
		ref, err := name.ParseReference(defaultFuzzRef)
		if err != nil {
			panic(err)
		}
		sigs, err := loadSignatureFromFile(context.Background(), sigPath, ref, &CheckOpts{PayloadRef: payloadPath})
		if err != nil {
			return
		}
		switch verificationTest % 5 {
		case 0:
			VerifyImageAttestation(context.Background(), sigs, v1.Hash{}, &CheckOpts{IgnoreTlog: true})
		case 1:
			verifySignatures(context.Background(), sigs, v1.Hash{}, &CheckOpts{IgnoreTlog: true})
		case 2:
			sl, err := sigs.Get()
			if err != nil {
				t.Fatal(err)
			}
			for _, sig := range sl {
				VerifyBlobSignature(context.Background(), sig, &CheckOpts{IgnoreTlog: true})
			}
		case 3:
			sl, err := sigs.Get()
			if err != nil {
				t.Fatal(err)
			}
			for _, sig := range sl {
				VerifyImageSignature(context.Background(), sig, v1.Hash{}, &CheckOpts{IgnoreTlog: true})
			}
		case 4:
			sl, err := sigs.Get()
			if err != nil {
				t.Fatal(err)
			}
			for _, sig := range sl {
				mutate.Signature(sig)
			}
		}
	})
}
