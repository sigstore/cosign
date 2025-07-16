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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
)

func TestCreateCmdDeprecatedFlags(t *testing.T) {
	ctx := context.Background()

	// Make some certificate chains
	td := t.TempDir()

	fulcioChainPath := filepath.Join(td, "fulcio.pem")
	makeChain(t, fulcioChainPath, false)

	tsaChainPathWithLeaf := filepath.Join(td, "timestamp_with_leaf.pem")
	makeChain(t, tsaChainPathWithLeaf, true)

	rekorV1KeyPath := filepath.Join(td, "rekor.v1.pub")
	makeKey(t, rekorV1KeyPath)
	rekorV2KeyPath := filepath.Join(td, "rekor.v2.pub")
	makeKey(t, rekorV2KeyPath)

	ctfeKeyPath := filepath.Join(td, "ctfe.pub")
	makeKey(t, ctfeKeyPath)

	outPath := filepath.Join(td, "trustedroot.json")

	trustedrootCreate := CreateCmd{
		CertChain:        []string{fulcioChainPath},
		FulcioURI:        []string{"https://fulcio.sigstore.example"},
		RekorURL:         []string{"https://rekor.sigstore.example"},
		RekorKeyPath:     []string{rekorV1KeyPath, rekorV2KeyPath + ",rekor.sigstore.example"},
		Out:              outPath,
		TSACertChainPath: []string{tsaChainPathWithLeaf},
		TSAURI:           []string{"https://tsa.sigstore.example"},
		CtfeKeyPath:      []string{ctfeKeyPath},
		CtfeURL:          []string{"https://ctfe.sigstore.example"},
		CtfeStartTime:    []string{"2023-01-01T00:00:00Z"},
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
	if len(timestampAuthorities[0].(*root.SigstoreTimestampingAuthority).Intermediates) != 1 {
		t.Fatal("unexpected number of timestamp intermediate certificates")
	}
	if timestampAuthorities[0].(*root.SigstoreTimestampingAuthority).Leaf == nil {
		t.Fatal("expected leaf certificate for timestamp authority")
	}

	ctLogs := tr.CTLogs()
	if len(ctLogs) != 1 {
		t.Fatalf("unexpected number of ctfe logs: %d", len(ctLogs))
	}

	tlogs := tr.RekorLogs()
	if len(tlogs) != 2 {
		t.Fatalf("unexpected number of rekor logs: %d", len(tlogs))
	}
	for _, tlog := range tlogs {
		if !tlog.ValidityPeriodEnd.IsZero() {
			t.Fatalf("unexpected validity period end for rekor log")
		}
	}

	trustedrootCreate.RekorEndTime = []string{"2286-11-20T09:46:40-08:00", "2286-11-20T09:46:40-08:00"}
	err = trustedrootCreate.Exec(ctx)
	checkErr(t, err)
	tr, err = root.NewTrustedRootFromPath(outPath)
	checkErr(t, err)
	tlogs = tr.RekorLogs()
	for _, tlog := range tlogs {
		expectedValidityEnd, _ := time.Parse(time.RFC3339, "2286-11-20T09:46:40-08:00")
		if !tlog.ValidityPeriodEnd.Equal(expectedValidityEnd) {
			t.Fatal("unexpected rekor log validity period end")
		}
	}
}

func TestCreateCmd(t *testing.T) {
	ctx := context.Background()
	td := t.TempDir()

	fulcioChainPath := filepath.Join(td, "fulcio.pem")
	makeChain(t, fulcioChainPath, false)

	tsaChainPath := filepath.Join(td, "timestamp.pem")
	makeChain(t, tsaChainPath, true)

	rekorV1KeyPath := filepath.Join(td, "rekor.v1.pub")
	makeKey(t, rekorV1KeyPath)

	rekorV2KeyPath := filepath.Join(td, "rekor.v2.pub")
	makeKey(t, rekorV2KeyPath)

	ctfeKeyPath := filepath.Join(td, "ctfe.pub")
	makeKey(t, ctfeKeyPath)

	outPath := filepath.Join(td, "trustedroot.json")
	startTime := "2023-01-01T00:00:00Z"
	endTime := "2025-01-01T00:00:00Z"

	fulcioSpec := fmt.Sprintf("url=https://fulcio.sigstore.example,certificate-chain=%s", fulcioChainPath)
	tsaSpec := fmt.Sprintf("url=https://timestmp.sigstore.example,certificate-chain=%s", tsaChainPath)
	rekorV1Spec := fmt.Sprintf("url=https://rekor.sigstore.example,public-key=%s,start-time=%s,end-time=%s", rekorV1KeyPath, startTime, endTime)
	rekorV2Spec := fmt.Sprintf("url=https://rekor.sigstore.example,public-key=%s,start-time=%s,origin=rekor-v2.sigstore.example", rekorV2KeyPath, startTime)
	ctfeSpec := fmt.Sprintf("url=https://ctfe.sigstore.example,public-key=%s,start-time=%s", ctfeKeyPath, startTime)

	trustedrootCreate := CreateCmd{
		FulcioSpecs: []string{fulcioSpec},
		RekorSpecs:  []string{rekorV1Spec, rekorV2Spec},
		TSASpecs:    []string{tsaSpec},
		CTFESpecs:   []string{ctfeSpec},
		Out:         outPath,
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
	if len(timestampAuthorities[0].(*root.SigstoreTimestampingAuthority).Intermediates) != 1 {
		t.Fatal("unexpected number of timestamp intermediate certificates")
	}
	if timestampAuthorities[0].(*root.SigstoreTimestampingAuthority).Leaf == nil {
		t.Fatal("expected leaf certificate for timestamp authority")
	}

	ctfeLogs := tr.CTLogs()
	if len(ctfeLogs) != 1 {
		t.Fatalf("unexpected number of ctfe logs: %d", len(ctfeLogs))
	}

	tlogs := tr.RekorLogs()
	if len(tlogs) != 2 {
		t.Fatalf("unexpected number of rekor logs: %d", len(tlogs))
	}
	// Check that one of the rekor logs has an end time set
	var foundWithEndTime bool
	expectedEndTime, _ := time.Parse(time.RFC3339, endTime)
	for _, tlog := range tlogs {
		if !tlog.ValidityPeriodEnd.IsZero() {
			if !tlog.ValidityPeriodEnd.Equal(expectedEndTime) {
				t.Fatalf("unexpected rekor log validity period end: got %v, want %v", tlog.ValidityPeriodEnd, expectedEndTime)
			}
			foundWithEndTime = true
		}
	}
	if !foundWithEndTime {
		t.Fatal("expected to find one rekor log with end time set")
	}

	// Test error when both new and old flags are used
	trustedrootCreate.CertChain = []string{fulcioChainPath}
	err = trustedrootCreate.Exec(ctx)
	if err == nil {
		t.Fatal("expected error when using both new and old flags")
	}
	trustedrootCreate.CertChain = nil // reset

	// Test TSA spec with no leaf certificate
	tsaChainNoLeafPath := filepath.Join(td, "tsa_no_leaf.pem")
	makeChain(t, tsaChainNoLeafPath, false) // This creates intermediate -> root
	tsaSpecNoLeaf := fmt.Sprintf("url=https://tsa.sigstore.example,certificate-chain=%s", tsaChainNoLeafPath)
	cmdCopy := trustedrootCreate
	cmdCopy.TSASpecs = []string{tsaSpecNoLeaf}
	err = cmdCopy.Exec(ctx)
	if err == nil {
		t.Fatal("expected error for TSA spec with no leaf certificate")
	}

	// Test missing and empty required fields for Fulcio
	for _, key := range []string{"url", "certificate-chain"} {
		// test missing key
		t.Run(fmt.Sprintf("fulcio missing %s", key), func(t *testing.T) {
			specMap := map[string]string{
				"url":               "https://fulcio.sigstore.example",
				"certificate-chain": fulcioChainPath,
			}
			delete(specMap, key)
			var pairs []string
			for k, v := range specMap {
				pairs = append(pairs, fmt.Sprintf("%s=%s", k, v))
			}
			badSpec := strings.Join(pairs, ",")

			cmdCopy := trustedrootCreate
			cmdCopy.FulcioSpecs = []string{badSpec}
			err := cmdCopy.Exec(ctx)
			if err == nil {
				t.Fatalf("expected error for missing required field '%s', but got none", key)
			}
		})
	}

	// Test missing and empty required fields for Rekor
	for _, key := range []string{"url", "public-key", "start-time"} {
		// test missing key
		t.Run(fmt.Sprintf("rekor missing %s", key), func(t *testing.T) {
			specMap := map[string]string{
				"url":        "https://rekor.sigstore.example",
				"public-key": rekorV1KeyPath,
				"start-time": startTime,
			}
			delete(specMap, key)
			var pairs []string
			for k, v := range specMap {
				pairs = append(pairs, fmt.Sprintf("%s=%s", k, v))
			}
			badSpec := strings.Join(pairs, ",")

			cmdCopy := trustedrootCreate
			cmdCopy.RekorSpecs = []string{badSpec}
			err := cmdCopy.Exec(ctx)
			if err == nil {
				t.Fatalf("expected error for missing required field '%s', but got none", key)
			}
		})
	}

	// Test missing and empty required fields for TSA
	for _, key := range []string{"url", "certificate-chain"} {
		// test missing key
		t.Run(fmt.Sprintf("tsa missing %s", key), func(t *testing.T) {
			specMap := map[string]string{
				"url":               "https://tsa.sigstore.example",
				"certificate-chain": tsaChainPath,
			}
			delete(specMap, key)
			var pairs []string
			for k, v := range specMap {
				pairs = append(pairs, fmt.Sprintf("%s=%s", k, v))
			}
			badSpec := strings.Join(pairs, ",")

			cmdCopy := trustedrootCreate
			cmdCopy.TSASpecs = []string{badSpec}
			err := cmdCopy.Exec(ctx)
			if err == nil {
				t.Fatalf("expected error for missing required field '%s', but got none", key)
			}
		})
	}

	// Test missing and empty required fields for CTFE
	for _, key := range []string{"url", "public-key", "start-time"} {
		// test missing key
		t.Run(fmt.Sprintf("ctfe missing %s", key), func(t *testing.T) {
			specMap := map[string]string{
				"url":        "https://ctfe.sigstore.dev",
				"public-key": ctfeKeyPath,
				"start-time": startTime,
			}
			delete(specMap, key)
			var pairs []string
			for k, v := range specMap {
				pairs = append(pairs, fmt.Sprintf("%s=%s", k, v))
			}
			badSpec := strings.Join(pairs, ",")

			cmdCopy := trustedrootCreate
			cmdCopy.CTFESpecs = []string{badSpec}
			err := cmdCopy.Exec(ctx)
			if err == nil {
				t.Fatalf("expected error for missing required field '%s', but got none", key)
			}
		})
	}
}

func makeChain(t *testing.T, path string, withLeaf bool) {
	fd, err := os.Create(path)
	checkErr(t, err)

	defer fd.Close()

	// Create root
	rootCertTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	checkErr(t, err)
	rootDer, err := x509.CreateCertificate(rand.Reader, rootCertTmpl, rootCertTmpl, &rootKey.PublicKey, rootKey)
	checkErr(t, err)
	rootCert, err := x509.ParseCertificate(rootDer)
	checkErr(t, err)

	// Create intermediate
	intermediateCertTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	checkErr(t, err)
	intermediateDer, err := x509.CreateCertificate(rand.Reader, intermediateCertTmpl, rootCert, &intermediateKey.PublicKey, rootKey)
	checkErr(t, err)

	intermediateCert, err := x509.ParseCertificate(intermediateDer)
	checkErr(t, err)

	if withLeaf {
		// Create leaf
		leafCertTmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(3),
			BasicConstraintsValid: true,
			IsCA:                  false, // This is a leaf
		}
		leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		checkErr(t, err)
		leafDer, err := x509.CreateCertificate(rand.Reader, leafCertTmpl, intermediateCert, &leafKey.PublicKey, intermediateKey)
		checkErr(t, err)

		// Write leaf first
		err = pem.Encode(fd, &pem.Block{Type: "CERTIFICATE", Bytes: leafDer})
		checkErr(t, err)
	}

	// Write intermediate
	err = pem.Encode(fd, &pem.Block{Type: "CERTIFICATE", Bytes: intermediateDer})
	checkErr(t, err)

	// Write out root last
	err = pem.Encode(fd, &pem.Block{Type: "CERTIFICATE", Bytes: rootDer})
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
