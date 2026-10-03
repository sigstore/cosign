//
// Copyright 2026 The Sigstore Authors.
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
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

// A --key verifier for an Ed25519 key must accept the signature a bundle
// actually carries, whichever of the two schemes made it.
func TestEd25519CompatibleVerifierAcceptsBothSchemes(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("signed content")

	prehashedSigner, err := signature.LoadDefaultSignerVerifier(priv, options.WithED25519ph())
	if err != nil {
		t.Fatal(err)
	}
	pureSigner, err := signature.LoadDefaultSignerVerifier(priv)
	if err != nil {
		t.Fatal(err)
	}
	prehashedSig, err := prehashedSigner.SignMessage(bytes.NewReader(message))
	if err != nil {
		t.Fatal(err)
	}
	pureSig, err := pureSigner.SignMessage(bytes.NewReader(message))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(prehashedSig, pureSig) {
		t.Fatal("the two schemes produced the same signature; the test proves nothing")
	}

	// What LoadDefaultVerifier hands back for an Ed25519 --key today.
	loaded, err := signature.LoadDefaultVerifier(pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := loaded.VerifySignature(bytes.NewReader(prehashedSig), bytes.NewReader(message)); err == nil {
		t.Fatal("a pure Ed25519 verifier accepted an Ed25519ph signature; the compat wrapper is no longer needed")
	}

	compat := ed25519CompatibleVerifier(loaded)
	for name, sig := range map[string][]byte{"ed25519ph": prehashedSig, "pure ed25519": pureSig} {
		if err := compat.VerifySignature(bytes.NewReader(sig), bytes.NewReader(message)); err != nil {
			t.Errorf("%s signature rejected: %v", name, err)
		}
	}
	if err := compat.VerifySignature(bytes.NewReader(pureSig), bytes.NewReader([]byte("other content"))); err == nil {
		t.Error("a signature over different content was accepted")
	}
	got, err := compat.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Equal(got) {
		t.Error("the wrapper must report the same public key")
	}
}

func TestEd25519CompatibleVerifierLeavesOtherKeysAlone(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := signature.LoadDefaultVerifier(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if ed25519CompatibleVerifier(verifier) != verifier {
		t.Fatal("a non-Ed25519 verifier must be returned unchanged")
	}
}
