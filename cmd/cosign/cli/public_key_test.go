//
// Copyright 2021 The Sigstore Authors.
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

package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/sigstore/cosign/pkg/cosign"
)

func pass(s string) cosign.PassFunc {
	return func(_ bool) ([]byte, error) {
		return []byte(s), nil
	}
}

// Test success on getting public key with valid keypair.
func TestPublicKeyLocation(t *testing.T) {
	ctx := context.Background()
	// Generate a valid keypair.
	keys, err := cosign.GenerateKeyPair(pass("hello"))
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	w := NamedWriter{"cosign.pub", &out}

	td := t.TempDir()
	f := filepath.Join(td, "private.key")
	if err := ioutil.WriteFile(f, keys.PrivateBytes, 0644); err != nil {
		t.Fatal(err)
	}

	opts := Pkopts{
		KeyRef: f,
	}
	err = GetPublicKey(ctx, opts, w, pass("hello"))
	if err != nil {
		t.Fatalf("got error %s", err)
	}

	// Verify that key's public key matches the output buffer.
	if !bytes.Equal(out.Bytes(), keys.PublicBytes) {
		t.Fatalf("expect %s got %s", keys.PrivateBytes, out.Bytes())
	}
}

// Tests failure with bad private key.
func TestPublicKeyBadPrivateKey(t *testing.T) {
	ctx := context.Background()
	// Use random bytes for private key pair.
	buf := []byte{}
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	td := t.TempDir()
	f := filepath.Join(td, "private.key")
	if err := ioutil.WriteFile(f, buf, 0644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	w := NamedWriter{"cosign.pub", &out}
	opts := Pkopts{
		KeyRef: f,
	}
	if err := GetPublicKey(ctx, opts, w, pass("hello")); err == nil {
		t.Error("expected error getting public key!")
	}
}
