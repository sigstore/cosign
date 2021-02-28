/*
Copyright The Rekor Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cosign

import (
	"crypto/rand"
	"testing"
)

func pass(s string) PassFunc {
	return func(_ bool) ([]byte, error) {
		return []byte(s), nil
	}
}

func TestLoadPrivateKey(t *testing.T) {
	// Generate a valid keypair
	keys, err := GenerateKeyPair(pass("hello"))
	if err != nil {
		t.Fatal(err)
	}

	// Load the private key with the right password
	if _, err := LoadPrivateKey(keys.PrivateBytes, []byte("hello")); err != nil {
		t.Errorf("unexpected error decrypting key: %s", err)
	}

	// Try it with the wrong one
	if _, err := LoadPrivateKey(keys.PrivateBytes, []byte("wrong")); err == nil {
		t.Error("expected error decrypting key!")
	}

	// Try to decrypt garbage
	buf := [100]byte{}
	if _, err := rand.Read(buf[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateKey(buf[:], []byte("wrong")); err == nil {
		t.Error("expected error decrypting key!")
	}

}
