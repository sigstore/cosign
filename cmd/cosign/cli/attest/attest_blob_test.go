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

package attest

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/pkg/errors"
	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/test"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	"github.com/theupdateframework/go-tuf/encrypted"
)

// TestAttestBlobCmdLocalKeyAndSk verifies the AttestBlobCmd returns an error
// if both a local key path and a sk are specified
func TestAttestBlobCmdLocalKeyAndSk(t *testing.T) {
	ctx := context.Background()
	for _, ko := range []options.KeyOpts{
		// local and sk keys
		{
			KeyRef:   "testLocalPath",
			PassFunc: generate.GetPass,
			Sk:       true,
		},
	} {
		at := AttestBlobCommand{
			KeyOpts: ko,
		}
		err := at.Exec(ctx, "some/path")
		if (errors.Is(err, &options.KeyParseError{}) == false) {
			t.Fatal("expected KeyParseError")
		}
	}
}

func writeFile(t *testing.T, td string, blob string, name string) string {
	// Write blob to disk
	blobPath := filepath.Join(td, name)
	if err := os.WriteFile(blobPath, []byte(blob), 0644); err != nil {
		t.Fatal(err)
	}
	return blobPath
}

// TestAttestBlobCmdWithCert verifies the AttestBlobCmd checks
// that the cmd correctly matches the signing key with the cert
// provided.
func TestAttestBlobCmdLocalKeyAndCert(t *testing.T) {
	td := t.TempDir()
	rootCert, rootKey, _ := test.GenerateRootCa()
	subCert, subKey, _ := test.GenerateSubordinateCa(rootCert, rootKey)
	leafCert, privKey, _ := test.GenerateLeafCert("subject", "oidc-issuer", subCert, subKey)
	pemChain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: subCert.Raw})
	subCertPem := writeFile(t, td, string(pemChain), "other_cert.pem")
	pemChain = append(pemChain,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Raw})...)
	pemLeaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Raw})

	otherRootCert, _, _ := test.GenerateRootCa()
	pemOtherRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: otherRootCert.Raw})
	otherRootPem := writeFile(t, td, string(pemOtherRoot), "other_root_cert.pem")

	x509Encoded, _ := x509.MarshalPKCS8PrivateKey(privKey)
	encBytes, _ := encrypted.Encrypt(x509Encoded, nil)
	keyPem := pem.EncodeToMemory(&pem.Block{
		Type:  cosign.CosignPrivateKeyPemType,
		Bytes: encBytes})
	keyRef := writeFile(t, td, string(keyPem), "key.pem")
	certRef := writeFile(t, td, string(pemLeaf), "cert.pem")
	chainRef := writeFile(t, td, string(pemChain), "chain.pem")

	blob := writeFile(t, td, "foo", "foo.txt")
	predicate := `{ "buildType": "x", "builder": { "id": "2" }, "recipe": {} }`
	predicateType := "slsaprovenance"
	predicatePath := writeFile(t, td, predicate, "predicate.json")

	ctx := context.Background()
	for _, tc := range []struct {
		name         string
		keyref       string
		certref      string
		certchainref string
		errString    string
	}{
		{
			name:   "no cert",
			keyref: keyRef,
		},
		{
			name:    "cert matches key",
			keyref:  keyRef,
			certref: certRef,
		},
		{
			name:      "fail: cert no match key",
			keyref:    keyRef,
			certref:   subCertPem,
			errString: "public key in certificate does not match the provided public key",
		},
		{
			name:         "cert chain matches key",
			keyref:       keyRef,
			certref:      certRef,
			certchainref: chainRef,
		},
		{
			name:         "cert chain partial",
			keyref:       keyRef,
			certref:      certRef,
			certchainref: subCertPem,
		},
		{
			name:         "fail: cert chain bad",
			keyref:       keyRef,
			certref:      certRef,
			certchainref: otherRootPem,
			errString:    "unable to validate certificate chain",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			at := AttestBlobCommand{
				KeyOpts:       options.KeyOpts{KeyRef: tc.keyref},
				CertPath:      tc.certref,
				CertChainPath: tc.certchainref,
				PredicatePath: predicatePath,
				PredicateType: predicateType,
			}
			err := at.Exec(ctx, blob)
			if err != nil {
				if tc.errString == "" {
					t.Fatalf("unexpected error %v", err)
				}
				if !strings.Contains(err.Error(), tc.errString) {
					t.Fatalf("expected error %v got %v", tc.errString, err)
				}
				return
			}
			if tc.errString != "" {
				t.Fatalf("expected error %v", tc.errString)
			}
		})
	}
}

// TestAttestBlob tests the main functionality -- does the command produce
// a validly signed DSSE envelope? (Using an on disk key)
func TestAttestBlob(t *testing.T) {
	ctx := context.Background()
	td := t.TempDir()

	keys, _ := cosign.GenerateKeyPair(nil)
	keyRef := writeFile(t, td, string(keys.PrivateBytes), "key.pem")
	pubKeyRef := writeFile(t, td, string(keys.PublicBytes), "key.pub")

	blob := []byte("foo")
	blobPath := writeFile(t, td, string(blob), "foo.txt")
	digest, _, _ := signature.ComputeDigestForSigning(bytes.NewReader(blob), crypto.SHA256, []crypto.Hash{crypto.SHA256, crypto.SHA384})
	blobDigest := strings.ToLower(hex.EncodeToString(digest))
	predicate := `{ "buildType": "x", "builder": { "id": "2" }, "recipe": {} }`
	predicateType := "slsaprovenance"
	predicatePath := writeFile(t, td, predicate, "predicate.json")

	dssePath := filepath.Join(td, "dsse.intoto.jsonl")
	at := AttestBlobCommand{
		KeyOpts:         options.KeyOpts{KeyRef: keyRef},
		PredicatePath:   predicatePath,
		PredicateType:   predicateType,
		OutputSignature: dssePath,
	}
	err := at.Exec(ctx, blobPath)
	if err != nil {
		t.Fatal(err)
	}

	// Load the attestation.
	dsseBytes, _ := os.ReadFile(dssePath)
	env := &ssldsse.Envelope{}
	if err := json.Unmarshal(dsseBytes, env); err != nil {
		t.Fatal(err)
	}

	if len(env.Signatures) != 1 {
		t.Fatalf("expected 1 signature, got %d", len(env.Signatures))
	}

	// Verify the subject digest
	decodedPredicate, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatalf("decoding dsse payload: %v", err)
	}
	var statement in_toto.Statement
	if err := json.Unmarshal(decodedPredicate, &statement); err != nil {
		t.Fatalf("decoding predicate: %v", err)
	}
	if statement.Subject == nil || len(statement.Subject) != 1 {
		t.Fatalf("expected one subject in intoto statement")
	}
	if statement.Subject[0].Digest["sha256"] != blobDigest {
		t.Fatalf("expected matching digest")
	}
	if statement.PredicateType != options.PredicateTypeMap[predicateType] {
		t.Fatalf("expected matching predicate type")
	}

	// Load a verifier and DSSE verify
	verifier, _ := signature.LoadVerifierFromPEMFile(pubKeyRef, crypto.SHA256)
	dssev, err := ssldsse.NewEnvelopeVerifier(&dsse.VerifierAdapter{SignatureVerifier: verifier})
	if err != nil {
		t.Fatalf("new envelope verifier: %v", err)
	}
	if _, err := dssev.Verify(env); err != nil {
		t.Fatalf("dsse verify: %v", err)
	}
}
