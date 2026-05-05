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

package bundle

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"net/url"
	"time"

	"crypto"
	"crypto/sha256"

	"github.com/sigstore/cosign/v3/internal/pkg/cosign/tsa"
	tsaMock "github.com/sigstore/cosign/v3/internal/pkg/cosign/tsa/mock"
	"github.com/sigstore/cosign/v3/internal/test"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	rekorv1 "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestInspectCmd(t *testing.T) {
	rootCert, rootKey, err := test.GenerateRootCa()
	if err != nil {
		t.Fatal(err)
	}
	leafCert, _, err := test.GenerateLeafCert("subject@mail.com", "oidc-issuer", rootCert, rootKey)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name            string
		bundle          *protobundle.Bundle
		expectedOutputs []string
	}{
		{
			name: "v0.3 bundle with signle cert",
			bundle: &protobundle.Bundle{
				MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
				VerificationMaterial: &protobundle.VerificationMaterial{
					Content: &protobundle.VerificationMaterial_Certificate{
						Certificate: &protocommon.X509Certificate{RawBytes: leafCert.Raw},
					},
				},
				Content: &protobundle.Bundle_MessageSignature{
					MessageSignature: &protocommon.MessageSignature{
						Signature: []byte("sig"),
					},
				},
			},
			expectedOutputs: []string{"Bundle Media Type", "Verification Material", "X.509 Certificate", "Message Signature"},
		},
		{
			name: "v0.1 bundle with single cert",
			bundle: &protobundle.Bundle{
				MediaType: "application/vnd.dev.sigstore.bundle+json;version=0.1",
				VerificationMaterial: &protobundle.VerificationMaterial{
					Content: &protobundle.VerificationMaterial_Certificate{
						Certificate: &protocommon.X509Certificate{RawBytes: leafCert.Raw},
					},
				},
			},
			expectedOutputs: []string{"v0.1/v0.2 bundle should use certificate chain, not single certificate"},
		},
		{
			name: "v0.3 bundle with certificate chain",
			bundle: &protobundle.Bundle{
				MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
				VerificationMaterial: &protobundle.VerificationMaterial{
					Content: &protobundle.VerificationMaterial_X509CertificateChain{
						X509CertificateChain: &protocommon.X509CertificateChain{
							Certificates: []*protocommon.X509Certificate{{RawBytes: leafCert.Raw}},
						},
					},
				},
			},
			expectedOutputs: []string{"v0.3 bundle should use single certificate, not chain"},
		},
		{
			name: "v0.3 bundle with public key",
			bundle: &protobundle.Bundle{
				MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
				VerificationMaterial: &protobundle.VerificationMaterial{
					Content: &protobundle.VerificationMaterial_PublicKey{
						PublicKey: &protocommon.PublicKeyIdentifier{Hint: "amtiZEdWemRDaz0="},
					},
				},
			},
			expectedOutputs: []string{"Public Key Identifier", "Hint"},
		},
		{
			name: "Bundle with missing media type",
			bundle: &protobundle.Bundle{
				MediaType: "",
			},
			expectedOutputs: []string{"Missing Bundle Media Type"},
		},
		{
			name: "Bundle with unrecognized media type",
			bundle: &protobundle.Bundle{
				MediaType: "application/garbage",
			},
			expectedOutputs: []string{"Unrecognized Media Type"},
		},
		{
			name: "Bundle with missing verification material",
			bundle: &protobundle.Bundle{
				MediaType:            "application/vnd.dev.sigstore.bundle.v0.3+json",
				VerificationMaterial: nil,
			},
			expectedOutputs: []string{"Missing Verification Material"},
		},
		{
			name: "Bundle with missing content",
			bundle: &protobundle.Bundle{
				MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
				VerificationMaterial: &protobundle.VerificationMaterial{
					Content: &protobundle.VerificationMaterial_Certificate{
						Certificate: &protocommon.X509Certificate{RawBytes: leafCert.Raw},
					},
				},
				Content: nil,
			},
			expectedOutputs: []string{"Missing Content"},
		},
		{
			name: "v0.1 bundle with tlog entry missing promise",
			bundle: &protobundle.Bundle{
				MediaType: "application/vnd.dev.sigstore.bundle+json;version=0.1",
				VerificationMaterial: &protobundle.VerificationMaterial{
					Content: &protobundle.VerificationMaterial_Certificate{
						Certificate: &protocommon.X509Certificate{RawBytes: leafCert.Raw},
					},
					TlogEntries: []*rekorv1.TransparencyLogEntry{
						{LogIndex: 123},
					},
				},
			},
			expectedOutputs: []string{"v0.1 bundle tlog entry MUST contain an inclusion promise"},
		},
		{
			name: "v0.3 bundle with tlog entry missing proof",
			bundle: &protobundle.Bundle{
				MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
				VerificationMaterial: &protobundle.VerificationMaterial{
					Content: &protobundle.VerificationMaterial_Certificate{
						Certificate: &protocommon.X509Certificate{RawBytes: leafCert.Raw},
					},
					TlogEntries: []*rekorv1.TransparencyLogEntry{
						{LogIndex: 456},
					},
				},
			},
			expectedOutputs: []string{"v0.3 bundle tlog entry MUST contain an inclusion proof"},
		},
		{
			name: "v0.3 bundle with empty certificate raw_bytes",
			bundle: &protobundle.Bundle{
				MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
				VerificationMaterial: &protobundle.VerificationMaterial{
					Content: &protobundle.VerificationMaterial_Certificate{
						Certificate: &protocommon.X509Certificate{RawBytes: []byte{}},
					},
				},
			},
			expectedOutputs: []string{"Certificate raw_bytes is empty"},
		},
		{
			name: "v0.3 bundle with empty certificate chain",
			bundle: &protobundle.Bundle{
				MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
				VerificationMaterial: &protobundle.VerificationMaterial{
					Content: &protobundle.VerificationMaterial_X509CertificateChain{
						X509CertificateChain: &protocommon.X509CertificateChain{
							Certificates: []*protocommon.X509Certificate{},
						},
					},
				},
			},
			expectedOutputs: []string{"Certificate chain is empty"},
		},
		{
			name: "v0.3 bundle with missing verification material content",
			bundle: &protobundle.Bundle{
				MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
				VerificationMaterial: &protobundle.VerificationMaterial{
					Content: nil,
				},
			},
			expectedOutputs: []string{"Missing Verification Material Content (must be certificate, chain, or public key)"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			jsonData, err := protojson.Marshal(tc.bundle)
			if err != nil {
				t.Fatal(err)
			}

			tmpDir := t.TempDir()
			bundleFile := filepath.Join(tmpDir, "bundle.json")
			err = os.WriteFile(bundleFile, jsonData, 0600)
			if err != nil {
				t.Fatal(err)
			}

			var buf bytes.Buffer
			cmd := &InspectCmd{
				BundlePath: bundleFile,
				Out:        &buf,
			}

			err = cmd.Exec()
			if err != nil {
				t.Fatal(err)
			}

			output := buf.String()

			for _, expected := range tc.expectedOutputs {
				if !strings.Contains(output, expected) {
					t.Errorf("expected output to contain %q, got:\n%s", expected, output)
				}
			}
		})
	}
}

func TestPopulateCertificateSummary(t *testing.T) {
	genCert := func(t *testing.T, pub any, priv any) []byte {
		parsedURL, _ := url.Parse("https://example.com")
		oidcIssuerOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
		issuerBytes, _ := asn1.Marshal("https://issuer.example.com")

		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName: "test",
			},
			NotBefore:      time.Now(),
			NotAfter:       time.Now().Add(time.Hour),
			EmailAddresses: []string{"test@example.com"},
			URIs:           []*url.URL{parsedURL},
			KeyUsage:       x509.KeyUsageDigitalSignature,
			ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			SubjectKeyId:   []byte{1, 2, 3, 4},
			AuthorityKeyId: []byte{5, 6, 7, 8},
			ExtraExtensions: []pkix.Extension{
				{
					Id:       oidcIssuerOID,
					Critical: false,
					Value:    issuerBytes,
				},
			},
		}
		certBytes, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
		if err != nil {
			t.Fatal(err)
		}
		return certBytes
	}

	ecdsaPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecdsaCert := genCert(t, &ecdsaPriv.PublicKey, ecdsaPriv)

	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	edCert := genCert(t, edPub, edPriv)

	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaCert := genCert(t, &rsaPriv.PublicKey, rsaPriv)

	tests := []struct {
		name          string
		certBytes     []byte
		expectedLabel string
		expectedValue string
	}{
		{
			name:          "ECDSA",
			certBytes:     ecdsaCert,
			expectedLabel: "Algorithm",
			expectedValue: "ECDSA",
		},
		{
			name:          "Ed25519",
			certBytes:     edCert,
			expectedLabel: "Algorithm",
			expectedValue: "Ed25519",
		},
		{
			name:          "RSA",
			certBytes:     rsaCert,
			expectedLabel: "Algorithm",
			expectedValue: "RSA",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			n := &node{}
			populateCertificateSummary(n, tc.certBytes)

			found := false
			for _, child := range n.Children {
				if child.Label == "Subject Public Key Info" {
					for _, grandChild := range child.Children {
						if grandChild.Label == tc.expectedLabel && grandChild.Value == tc.expectedValue {
							found = true
							break
						}
					}
				}
			}
			if !found {
				t.Errorf("expected child with label %s and value %s under 'Subject Public Key Info'", tc.expectedLabel, tc.expectedValue)
			}
		})
	}
}

func TestPopulateTlogEntrySummary(t *testing.T) {
	tests := []struct {
		name          string
		entry         *rekorv1.TransparencyLogEntry
		expectedPairs map[string]string
	}{
		{
			name: "Generic Log",
			entry: &rekorv1.TransparencyLogEntry{
				LogIndex: 123,
				LogId: &protocommon.LogId{
					KeyId: []byte("log-id"),
				},
			},
			expectedPairs: map[string]string{
				"Log Index": "123",
				"Log ID":    "6c6f672d6964",
			},
		},
		{
			name: "Rekor v1 Prod",
			entry: &rekorv1.TransparencyLogEntry{
				LogIndex: 456,
				LogId: &protocommon.LogId{
					KeyId: func() []byte {
						b, _ := hex.DecodeString(rekorV1ProdLogID)
						return b
					}(),
				},
			},
			expectedPairs: map[string]string{
				"Log Index": "456",
				"Log":       "Rekor v1",
			},
		},
		{
			name: "Rekor v1 Staging",
			entry: &rekorv1.TransparencyLogEntry{
				LogIndex: 789,
				LogId: &protocommon.LogId{
					KeyId: func() []byte {
						b, _ := hex.DecodeString(rekorV1StagingLogID)
						return b
					}(),
				},
			},
			expectedPairs: map[string]string{
				"Log Index": "789",
				"Log":       "Rekor v1 (Staging)",
			},
		},
		{
			name: "Rekor v2 Prod",
			entry: &rekorv1.TransparencyLogEntry{
				LogIndex: 101,
				LogId: &protocommon.LogId{
					KeyId: func() []byte {
						b, _ := hex.DecodeString(rekorV2ProdLogID)
						return b
					}(),
				},
			},
			expectedPairs: map[string]string{
				"Log Index": "101",
				"Log":       "Rekor v2",
			},
		},
		{
			name: "Rekor v2 Staging",
			entry: &rekorv1.TransparencyLogEntry{
				LogIndex: 202,
				LogId: &protocommon.LogId{
					KeyId: func() []byte {
						b, _ := hex.DecodeString(rekorV2StagingLogID)
						return b
					}(),
				},
			},
			expectedPairs: map[string]string{
				"Log Index": "202",
				"Log":       "Rekor v2 (Staging)",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			n := &node{}
			populateTlogEntrySummary(n, tc.entry)

			for expectedLabel, expectedValue := range tc.expectedPairs {
				found := false
				for _, child := range n.Children {
					if child.Label == expectedLabel && child.Value == expectedValue {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected child with label %s and value %s", expectedLabel, expectedValue)
				}
			}
		})
	}
}

func TestPopulateContentSummary(t *testing.T) {
	tests := []struct {
		name          string
		bundleContent *protobundle.Bundle
		expectedLabel string
		expectedValue string
	}{
		{
			name: "DSSE Envelope",
			bundleContent: &protobundle.Bundle{
				Content: &protobundle.Bundle_DsseEnvelope{
					DsseEnvelope: &protodsse.Envelope{
						PayloadType: "application/vnd.in-toto+json",
						Payload:     []byte(`{"predicateType":"https://in-toto.io/Attestation/GitHubWorkflow/v0.1","subject":[{"name":"foo"}]}`),
					},
				},
			},
			expectedLabel: "Type",
			expectedValue: "DSSE Envelope",
		},
		{
			name: "Message Signature",
			bundleContent: &protobundle.Bundle{
				Content: &protobundle.Bundle_MessageSignature{
					MessageSignature: &protocommon.MessageSignature{
						MessageDigest: &protocommon.HashOutput{
							Algorithm: protocommon.HashAlgorithm_SHA2_256,
							Digest:    []byte("digest"),
						},
						Signature: []byte("signature"),
					},
				},
			},
			expectedLabel: "Type",
			expectedValue: "Message Signature",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			n := &node{}
			populateContentSummary(n, tc.bundleContent)

			found := false
			for _, child := range n.Children {
				if child.Label == "Content" {
					for _, grandChild := range child.Children {
						if grandChild.Label == tc.expectedLabel && grandChild.Value == tc.expectedValue {
							found = true
							break
						}
					}
				}
			}
			if !found {
				t.Errorf("expected child with label %s and value %s", tc.expectedLabel, tc.expectedValue)
			}
		})
	}
}

func TestPopulateTimestampSummary(t *testing.T) {
	payload := []byte{1, 2, 3, 4}
	h := sha256.Sum256(payload)

	ecdsaPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signature, err := ecdsaPriv.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	client, err := tsaMock.NewTSAClient(tsaMock.TSAClientOptions{Time: time.Now()})
	if err != nil {
		t.Fatal(err)
	}

	tsBytes, err := tsa.GetTimestampedSignature(signature, client)
	if err != nil {
		t.Fatal(err)
	}

	n := &node{}
	tsData := &protobundle.TimestampVerificationData{
		Rfc3161Timestamps: []*protocommon.RFC3161SignedTimestamp{
			{SignedTimestamp: tsBytes},
		},
	}

	populateTimestampSummary(n, tsData)

	if len(n.Children) == 0 {
		t.Error("expected children, got none")
	}

	found := false
	for _, child := range n.Children {
		if child.Label == "RFC3161 Timestamps" && child.Value == "1" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'RFC3161 Timestamps' with value '1'")
	}
}

func TestPopulateContentSummary_DsseSignatures(t *testing.T) {
	tests := []struct {
		name           string
		bundle         *protobundle.Bundle
		expectedLabels []string
		expectedValues []string
	}{
		{
			name: "Valid Base64 Key Hint",
			bundle: &protobundle.Bundle{
				Content: &protobundle.Bundle_DsseEnvelope{
					DsseEnvelope: &protodsse.Envelope{
						Signatures: []*protodsse.Signature{
							{
								Sig:   []byte("sig1"),
								Keyid: "dGVzdC1oaW50", // base64 decodes to "test-hint"
							},
						},
					},
				},
			},
			expectedLabels: []string{"Key Hint"},
			expectedValues: []string{"746573742d68696e74"}, // hex of "test-hint"
		},
		{
			name: "Invalid Base64 Key Hint",
			bundle: &protobundle.Bundle{
				Content: &protobundle.Bundle_DsseEnvelope{
					DsseEnvelope: &protodsse.Envelope{
						Signatures: []*protodsse.Signature{
							{
								Sig:   []byte("sig2"),
								Keyid: "not-base64-!",
							},
						},
					},
				},
			},
			expectedLabels: []string{"Key Hint"},
			expectedValues: []string{"not-base64-!"},
		},
		{
			name: "Key Hint Mismatch",
			bundle: &protobundle.Bundle{
				VerificationMaterial: &protobundle.VerificationMaterial{
					Content: &protobundle.VerificationMaterial_PublicKey{
						PublicKey: &protocommon.PublicKeyIdentifier{
							Hint: "different-hint",
						},
					},
				},
				Content: &protobundle.Bundle_DsseEnvelope{
					DsseEnvelope: &protodsse.Envelope{
						Signatures: []*protodsse.Signature{
							{
								Sig:   []byte("sig3"),
								Keyid: "hint-1",
							},
						},
					},
				},
			},
			expectedLabels: []string{"Key Hint", "[!] WARNING"},
			expectedValues: []string{"hint-1", "Key hint mismatch with Verification Material"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			n := &node{}
			populateContentSummary(n, tc.bundle)

			// Helper function to recursively find nodes in the tree
			var findNodes func(n *node, label string) []*node
			findNodes = func(n *node, label string) []*node {
				var res []*node
				if n.Label == label {
					res = append(res, n)
				}
				for i := range n.Children {
					res = append(res, findNodes(&n.Children[i], label)...)
				}
				return res
			}

			for i, expectedLabel := range tc.expectedLabels {
				expectedValue := tc.expectedValues[i]
				nodes := findNodes(n, expectedLabel)
				found := false
				for _, matchingNode := range nodes {
					if matchingNode.Value == expectedValue {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected node with label %q and value %q to be present in tree", expectedLabel, expectedValue)
				}
			}
		})
	}
}

func TestPopulateTlogEntrySummary_Inclusion(t *testing.T) {
	t.Run("Inclusion promise", func(t *testing.T) {
		n := &node{}
		entry := &rekorv1.TransparencyLogEntry{
			InclusionPromise: &rekorv1.InclusionPromise{
				SignedEntryTimestamp: []byte("promise"),
			},
		}
		populateTlogEntrySummary(n, entry)

		var promiseNode *node
		for i := range n.Children {
			if n.Children[i].Label == "Inclusion Promise" {
				promiseNode = &n.Children[i]
				break
			}
		}
		if promiseNode == nil {
			t.Fatal("expected 'Inclusion Promise' node")
		}
		if len(promiseNode.Children) != 1 || promiseNode.Children[0].Label != "Signed Entry Timestamp" || promiseNode.Children[0].Value != "Present (7 bytes)" {
			t.Errorf("unexpected Inclusion Promise children: %v", promiseNode.Children)
		}
	})

	t.Run("Inclusion proof with invalid checkpoint", func(t *testing.T) {
		n := &node{}
		entry := &rekorv1.TransparencyLogEntry{
			InclusionProof: &rekorv1.InclusionProof{
				LogIndex: 123,
				TreeSize: 456,
				Hashes:   [][]byte{[]byte("h1")},
				Checkpoint: &rekorv1.Checkpoint{
					Envelope: "invalid",
				},
			},
		}
		populateTlogEntrySummary(n, entry)

		var proofNode *node
		for i := range n.Children {
			if n.Children[i].Label == "Inclusion Proof" {
				proofNode = &n.Children[i]
				break
			}
		}
		if proofNode == nil {
			t.Fatal("expected 'Inclusion Proof' node")
		}

		expectedProofFields := map[string]string{
			"Log Index": "123",
			"Tree Size": "456",
			"Hashes":    "1",
		}
		for _, child := range proofNode.Children {
			if val, ok := expectedProofFields[child.Label]; ok {
				if child.Value != val {
					t.Errorf("expected proof field %s to be %s, got %s", child.Label, val, child.Value)
				}
			}
		}

		var checkpointNode *node
		for i := range proofNode.Children {
			if proofNode.Children[i].Label == "Checkpoint" {
				checkpointNode = &proofNode.Children[i]
				break
			}
		}
		if checkpointNode == nil {
			t.Fatal("expected 'Checkpoint' node under proof")
		}
		if len(checkpointNode.Children) != 1 || checkpointNode.Children[0].Label != "Envelope" || checkpointNode.Children[0].Value != "Present (7 bytes)" {
			t.Errorf("unexpected Checkpoint children: %v", checkpointNode.Children)
		}
	})

	t.Run("Inclusion proof with valid checkpoint", func(t *testing.T) {
		n := &node{}
		validEnvelope := "rekor.sigstore.dev\n123\n47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\n\n— witness1 dGVzdC1zaWc=\n"
		entry := &rekorv1.TransparencyLogEntry{
			InclusionProof: &rekorv1.InclusionProof{
				LogIndex: 123,
				TreeSize: 456,
				Hashes:   [][]byte{[]byte("h1")},
				Checkpoint: &rekorv1.Checkpoint{
					Envelope: validEnvelope,
				},
			},
		}
		populateTlogEntrySummary(n, entry)

		var proofNode *node
		for i := range n.Children {
			if n.Children[i].Label == "Inclusion Proof" {
				proofNode = &n.Children[i]
				break
			}
		}
		if proofNode == nil {
			t.Fatal("expected 'Inclusion Proof' node")
		}

		var checkpointNode *node
		for i := range proofNode.Children {
			if proofNode.Children[i].Label == "Checkpoint" {
				checkpointNode = &proofNode.Children[i]
				break
			}
		}
		if checkpointNode == nil {
			t.Fatal("expected 'Checkpoint' node under proof")
		}

		hasOrigin := false
		expectedCheckpointFields := map[string]string{
			"Origin":    "rekor.sigstore.dev",
			"Tree Size": "123",
		}
		for _, child := range checkpointNode.Children {
			if child.Label == "Origin" {
				hasOrigin = true
			}
			if val, ok := expectedCheckpointFields[child.Label]; ok {
				if child.Value != val {
					t.Errorf("expected checkpoint field %s to be %s, got %s", child.Label, val, child.Value)
				}
			}
		}
		if !hasOrigin {
			t.Error("expected 'Origin' node, meaning checkpoint unmarshaling failed and hit fallback")
		}

		var witnessesNode *node
		for i := range checkpointNode.Children {
			if checkpointNode.Children[i].Label == "Witnesses" {
				witnessesNode = &checkpointNode.Children[i]
				break
			}
		}
		if witnessesNode == nil {
			t.Fatal("expected 'Witnesses' node under checkpoint")
		}
		if len(witnessesNode.Children) != 1 || witnessesNode.Children[0].Label != "witness1" || !strings.Contains(witnessesNode.Children[0].Value, "Signature Present") {
			t.Errorf("unexpected Witnesses children: %v", witnessesNode.Children)
		}
	})
}
