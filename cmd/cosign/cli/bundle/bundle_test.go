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

package bundle

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	sgBundle "github.com/sigstore/sigstore-go/pkg/bundle"
)

func TestCreateCmd(t *testing.T) {
	ctx := context.Background()

	artifact := "hello world"
	digest := sha256.Sum256([]byte(artifact))

	td := t.TempDir()
	artifactPath := filepath.Join(td, "artifact")
	err := os.WriteFile(artifactPath, []byte(artifact), 0600)
	checkErr(t, err)

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	checkErr(t, err)
	sigBytes, err := privateKey.Sign(rand.Reader, digest[:], crypto.SHA256)
	checkErr(t, err)

	signature := base64.StdEncoding.EncodeToString(sigBytes)
	sigPath := filepath.Join(td, "sig")
	err = os.WriteFile(sigPath, []byte(signature), 0600)
	checkErr(t, err)

	publicKeyPath := filepath.Join(td, "key.pub")
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	checkErr(t, err)
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}
	err = os.WriteFile(publicKeyPath, pem.EncodeToMemory(pemBlock), 0600)
	checkErr(t, err)

	outPath := filepath.Join(td, "bundle.sigstore.json")

	bundleCreate := CreateCmd{
		Artifact:      artifactPath,
		KeyRef:        publicKeyPath,
		IgnoreTlog:    true,
		Out:           outPath,
		SignaturePath: sigPath,
	}

	err = bundleCreate.Exec(ctx)
	checkErr(t, err)

	b, err := sgBundle.LoadJSONFromPath(outPath)
	checkErr(t, err)

	if b.Bundle.VerificationMaterial == nil {
		t.Fatal("bundle does not have verification material")
	}

	if b.Bundle.VerificationMaterial.GetPublicKey() == nil {
		t.Fatal("bundle verification material does not have public key")
	}

	if b.Bundle.GetMessageSignature() == nil {
		t.Fatal("bundle does not have message signature")
	}
}

func checkErr(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}
