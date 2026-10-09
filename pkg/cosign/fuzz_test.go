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
	"os"
	"path/filepath"
	"testing"
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
