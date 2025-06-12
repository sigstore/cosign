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

package trustedroot

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/root"
)

func TestCreateCmd(t *testing.T) {
	ctx := context.Background()

	// Make some certificate chains
	td := t.TempDir()

	fulcioChainPath := filepath.Join(td, "fulcio.pem")
	makeChain(t, fulcioChainPath, 2)

	tsaChainPath := filepath.Join(td, "timestamp.pem")
	makeChain(t, tsaChainPath, 3)

	rekorV1KeyPath := filepath.Join(td, "rekor.v1.pub")
	makeKey(t, rekorV1KeyPath)
	rekorV2KeyPath := filepath.Join(td, "rekor.v2.pub")
	makeKey(t, rekorV2KeyPath)

	outPath := filepath.Join(td, "trustedroot.json")

	trustedrootCreate := CreateCmd{
		CertChain:        []string{fulcioChainPath},
		FulcioURI:        []string{"https://fulcio.sigstore.example"},
		RekorURL:         []string{"https://rekor.sigstore.example"},
		RekorKeyPath:     []string{rekorV1KeyPath, rekorV2KeyPath + ",rekor.sigstore.example"},
		Out:              outPath,
		TSACertChainPath: []string{tsaChainPath},
		TSAURI:           []string{"https://tsa.sigstore.example"},
	}

	err := trustedrootCreate.Exec(ctx)
	checkErr(t, err)

	tr, err := root.NewTrustedRootFromPath(outPath)
	checkErr(t, err)

	fulcioCAs := tr.FulcioCertificateAuthorities()

	if len(fulcioCAs) != 1 {
		t.Fatal("unexpected number of fulcio certificate authorities")
	}

	if len(fulcioCAs[0].(*root.FulcioCertificateAuthority).Intermediates) != 1 {
		t.Fatal("unexpected number of fulcio intermediate certificates")
	}

	timestampAuthorities := tr.TimestampingAuthorities()
	if len(timestampAuthorities) != 1 {
		t.Fatal("unexpected number of timestamp authorities")
	}

	if len(timestampAuthorities[0].(*root.SigstoreTimestampingAuthority).Intermediates) != 2 {
		t.Fatal("unexpected number of timestamp intermediate certificates")
	}
}

func makeChain(t *testing.T, path string, size int) {
	fd, err := os.Create(path)
	checkErr(t, err)

	defer fd.Close()

	chainCert := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	chainKey, err := rsa.GenerateKey(rand.Reader, 4096)
	checkErr(t, err)
	rootDer, err := x509.CreateCertificate(rand.Reader, chainCert, chainCert, &chainKey.PublicKey, chainKey)
	checkErr(t, err)

	for i := 1; i < size; i++ {
		intermediateCert := &x509.Certificate{
			SerialNumber:          big.NewInt(1 + int64(i)),
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
		intermediateKey, err := rsa.GenerateKey(rand.Reader, 4096)
		checkErr(t, err)
		intermediateDer, err := x509.CreateCertificate(rand.Reader, intermediateCert, chainCert, &intermediateKey.PublicKey, chainKey)
		checkErr(t, err)

		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: intermediateDer,
		}
		err = pem.Encode(fd, block)
		checkErr(t, err)

		chainCert = intermediateCert
		chainKey = intermediateKey
	}

	// Write out root last
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: rootDer,
	}
	err = pem.Encode(fd, block)
	checkErr(t, err)

	// Ensure we handle unexpected content at the end of the PEM file
	_, err = fd.Write([]byte("asdf\n"))
	checkErr(t, err)
}

func makeKey(t *testing.T, path string) {
	fd, err := os.Create(path)
	checkErr(t, err)
	defer fd.Close()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	checkErr(t, err)
	derBytes, err := x509.MarshalPKIXPublicKey(pub)
	checkErr(t, err)
	err = pem.Encode(fd, &pem.Block{Type: "PUBLIC KEY", Bytes: derBytes})
	checkErr(t, err)
}

func checkErr(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}
