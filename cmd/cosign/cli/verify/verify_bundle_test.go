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

package verify

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/signature"
)

func TestVerifyBundleWithKey(t *testing.T) {
	// First assemble bundle
	ctx := context.Background()
	artifact := "hello world"
	digest := sha256.Sum256([]byte(artifact))

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	checkErr(t, err)
	sigBytes, err := privateKey.Sign(rand.Reader, digest[:], crypto.SHA256)
	checkErr(t, err)

	td := t.TempDir()
	artifactPath := filepath.Join(td, "artifact")
	err = os.WriteFile(artifactPath, []byte(artifact), 0600)
	checkErr(t, err)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	checkErr(t, err)
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}
	verifier, err := signature.LoadPublicKeyRaw(
		pem.EncodeToMemory(pemBlock), crypto.SHA256,
	)
	checkErr(t, err)

	bundle, err := assembleNewBundle(ctx, sigBytes, nil, nil, artifactPath, nil,
		true, verifier, nil, nil,
	)
	checkErr(t, err)

	if bundle == nil {
		t.Fatal("invalid bundle")
	}

	// The verify assembled bundle
	trustedRootPath := filepath.Join(td, "trusted_root.json")
	err = os.WriteFile(trustedRootPath, []byte(`{"mediaType":"application/vnd.dev.sigstore.trustedroot+json;version=0.1"}`), 0600)
	checkErr(t, err)

	publicKeyPath := filepath.Join(td, "key.pub")
	err = os.WriteFile(publicKeyPath, pem.EncodeToMemory(pemBlock), 0600)
	checkErr(t, err)

	co := &cosign.CheckOpts{}
	co.SigVerifier, err = signature.PublicKeyFromKeyRef(ctx, publicKeyPath)
	checkErr(t, err)

	var trustedroot *root.TrustedRoot
	co.TrustedMaterial, trustedroot, err = makeTrustedMaterial(trustedRootPath, &co.SigVerifier)
	checkErr(t, err)

	co.IdentityPolicies, err = makeIdentityPolicy(bundle, options.CertVerifyOptions{}, "", "", "", "", "")
	checkErr(t, err)

	co.VerifierOptions = makeVerifierOptions(trustedroot, true, false, true)

	result, err := verifyNewBundle(bundle, co, artifactPath)
	checkErr(t, err)

	if result == nil {
		t.Fatal("invalid verification result")
	}
}

func checkErr(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}
