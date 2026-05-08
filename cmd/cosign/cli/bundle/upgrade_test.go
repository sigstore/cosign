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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
)

type mockEntriesClient struct {
	entries.ClientService
	getLogEntryByIndexFunc func(params *entries.GetLogEntryByIndexParams, opts ...entries.ClientOption) (*entries.GetLogEntryByIndexOK, error)
}

func (m *mockEntriesClient) GetLogEntryByIndex(params *entries.GetLogEntryByIndexParams, opts ...entries.ClientOption) (*entries.GetLogEntryByIndexOK, error) {
	if m.getLogEntryByIndexFunc != nil {
		return m.getLogEntryByIndexFunc(params, opts...)
	}
	return nil, nil
}

func TestUpgradeBundle(t *testing.T) {
	checkV03 := func(expectedCertB64 string) func(t *testing.T, output []byte) {
		return func(t *testing.T, output []byte) {
			var m map[string]interface{}
			err := json.Unmarshal(output, &m)
			if err != nil {
				t.Fatalf("unmarshaling output: %v", err)
			}

			if m["mediaType"] != "application/vnd.dev.sigstore.bundle.v0.3+json" {
				t.Fatalf("expected mediaType to be 'application/vnd.dev.sigstore.bundle.v0.3+json', got %v", m["mediaType"])
			}

			vm, ok := m["verificationMaterial"].(map[string]interface{})
			if !ok {
				t.Fatal("missing verificationMaterial")
			}

			cert, ok := vm["certificate"].(map[string]interface{})
			if !ok {
				t.Fatal("missing certificate field in verificationMaterial")
			}

			if cert["rawBytes"] != expectedCertB64 {
				t.Fatalf("expected leaf certificate rawBytes to be %v, got %v", expectedCertB64, cert["rawBytes"])
			}
		}
	}

	genCert := func(cn string, emails []string, uris []string) string {
		cert, _, err := selfSignedCertificate(cn, emails, uris)
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(cert.Raw)
	}

	certEmailB64 := genCert("cert", []string{"foo@bar.com"}, nil)
	certURIB64 := genCert("cert", nil, []string{"https://example.com/workflow"})
	certSubjectB64 := genCert("my-identity", nil, nil)
	certNoneB64 := genCert("", nil, nil)

	tests := []struct {
		name        string
		input       string
		expectError bool
		checkOutput func(t *testing.T, output []byte)
		rekorClient *client.Rekor
	}{
		{
			name:  "Already v0.3",
			input: `{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","verificationMaterial":{"publicKey":{}}}`,
			checkOutput: func(t *testing.T, output []byte) {
				expected := `{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","verificationMaterial":{"publicKey":{}}}`
				if string(output) != expected {
					t.Fatal("expected output to match input")
				}
			},
		},
		{
			name: "Upgrade v0.1 to v0.3",
			input: `{
				"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
				"verificationMaterial": {
					"x509CertificateChain": {
						"certificates": [
							{"rawBytes": "bGVhZg=="},
							{"rawBytes": "aW50ZXJtZWRpYXRl"}
						]
					}
				}
			}`,
			checkOutput: checkV03("bGVhZg=="),
		},
		{
			name: "Upgrade v0.2 to v0.3",
			input: `{
				"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.2",
				"verificationMaterial": {
					"x509CertificateChain": {
						"certificates": [
							{"rawBytes": "bGVhZg=="},
							{"rawBytes": "aW50ZXJtZWRpYXRl"}
						]
					}
				}
			}`,
			checkOutput: checkV03("bGVhZg=="),
		},
		{
			name: "Upgrade with Email SAN",
			input: `{
				"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
				"verificationMaterial": {
					"x509CertificateChain": {
						"certificates": [
							{"rawBytes": "` + certEmailB64 + `"}
						]
					}
				}
			}`,
			checkOutput: checkV03(certEmailB64),
		},
		{
			name: "Upgrade with URI SAN",
			input: `{
				"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
				"verificationMaterial": {
					"x509CertificateChain": {
						"certificates": [
							{"rawBytes": "` + certURIB64 + `"}
						]
					}
				}
			}`,
			checkOutput: checkV03(certURIB64),
		},
		{
			name: "Upgrade with Subject",
			input: `{
				"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
				"verificationMaterial": {
					"x509CertificateChain": {
						"certificates": [
							{"rawBytes": "` + certSubjectB64 + `"}
						]
					}
				}
			}`,
			checkOutput: checkV03(certSubjectB64),
		},
		{
			name: "Upgrade with no identity",
			input: `{
				"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
				"verificationMaterial": {
					"x509CertificateChain": {
						"certificates": [
							{"rawBytes": "` + certNoneB64 + `"}
						]
					}
				}
			}`,
			checkOutput: checkV03(certNoneB64),
		},
		{
			name:        "Missing VerificationMaterial",
			input:       `{"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1"}`,
			expectError: true,
		},
		{
			name:        "Missing Content in VerificationMaterial",
			input:       `{"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1", "verificationMaterial": {}}`,
			expectError: true,
		},
		{
			name:        "Unsupported version",
			input:       `{"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.4", "verificationMaterial": {"publicKey": {}}}`,
			expectError: true,
		},
		{
			name: "Upgrade with missing inclusion proof",
			input: `{
				"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
				"verificationMaterial": {
					"x509CertificateChain": {
						"certificates": [
							{"rawBytes": "bGVhZg=="}
						]
					},
					"tlogEntries": [
						{
							"logIndex": 42,
							"inclusionPromise": {
								"signedEntryTimestamp": "c2ln"
							}
						}
					]
				}
			}`,
			rekorClient: &client.Rekor{
				Entries: &mockEntriesClient{
					getLogEntryByIndexFunc: func(_ *entries.GetLogEntryByIndexParams, _ ...entries.ClientOption) (*entries.GetLogEntryByIndexOK, error) {
						return &entries.GetLogEntryByIndexOK{
							Payload: models.LogEntry{
								"uuid": createMockLogEntryAnon(),
							},
						}, nil
					},
				},
			},
			checkOutput: func(t *testing.T, output []byte) {
				var m map[string]interface{}
				if err := json.Unmarshal(output, &m); err != nil {
					t.Fatalf("unmarshaling output: %v", err)
				}
				vm := m["verificationMaterial"].(map[string]interface{})
				tlogEntries := vm["tlogEntries"].([]interface{})
				entry := tlogEntries[0].(map[string]interface{})
				proof := entry["inclusionProof"].(map[string]interface{})
				if proof["logIndex"].(string) != "42" {
					t.Fatalf("expected logIndex 42, got %v", proof["logIndex"])
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, err := upgradeBundle(context.Background(), []byte(tc.input), tc.rekorClient)
			if tc.expectError {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if tc.checkOutput != nil {
					tc.checkOutput(t, out)
				}
			}
		})
	}
}

func TestUpgradeCmd(t *testing.T) {
	ctx := context.Background()

	t.Run("File Output", func(t *testing.T) {
		td := t.TempDir()

		inputPath := filepath.Join(td, "input.json")
		v01Bundle := `{
			"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
			"verificationMaterial": {
				"x509CertificateChain": {
					"certificates": [
						{"rawBytes": "bGVhZg=="}
					]
				}
			}
		}`
		err := os.WriteFile(inputPath, []byte(v01Bundle), 0600)
		if err != nil {
			t.Fatal(err)
		}

		outputPath := filepath.Join(td, "output.json")

		cmd := UpgradeCmd{
			Out: outputPath,
		}

		err = cmd.Exec(ctx, inputPath)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		data, err := os.ReadFile(outputPath)
		if err != nil {
			t.Fatal(err)
		}

		var m map[string]interface{}
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatal(err)
		}

		if m["mediaType"] != "application/vnd.dev.sigstore.bundle.v0.3+json" {
			t.Fatalf("expected mediaType to be 'application/vnd.dev.sigstore.bundle.v0.3+json', got %v", m["mediaType"])
		}
	})

	t.Run("Stdout Fallback", func(t *testing.T) {
		td := t.TempDir()

		inputPath := filepath.Join(td, "input.json")
		v01Bundle := `{
			"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
			"verificationMaterial": {
				"x509CertificateChain": {
					"certificates": [
						{"rawBytes": "bGVhZg=="}
					]
				}
			}
		}`
		err := os.WriteFile(inputPath, []byte(v01Bundle), 0600)
		if err != nil {
			t.Fatal(err)
		}

		cmd := UpgradeCmd{
			Out: "",
		}

		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal("failed to create a pipe for testing os.Stdout")
		}
		stdout := os.Stdout
		os.Stdout = writer

		err = cmd.Exec(ctx, inputPath)

		os.Stdout = stdout
		writer.Close()

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var buffer bytes.Buffer
		_, err = io.Copy(&buffer, reader)
		if err != nil {
			t.Fatal(err)
		}

		output := buffer.Bytes()
		var m map[string]interface{}
		if err := json.Unmarshal(output, &m); err != nil {
			t.Fatalf("unmarshaling stdout output: %v", err)
		}

		if m["mediaType"] != "application/vnd.dev.sigstore.bundle.v0.3+json" {
			t.Fatalf("expected mediaType to be 'application/vnd.dev.sigstore.bundle.v0.3+json', got %v", m["mediaType"])
		}
	})
}

func createMockLogEntryAnon() models.LogEntryAnon {
	body := "eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiIyMzBkODM1OGRjOGU4ODkwYjRjNThkZWViNjI5MTJlZTJmMjAzNTdhZTkyYTVjYzg2MWI5OGU2OGZlMzFhY2I1In19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FVUNJUURHcXFXL1Q4YzZqZTltSVFPaUNhZXdldWZpUmJXMC9YZVBJUmMxWVdXUVZBSWdNWjVlbmNvWFdNdjdUK3AxU0k1YUUzdzZOb3Zyb3RYdGVoMlV3V040SUJvPSIsInB1YmxpY0tleSI6eyJjb250ZW50IjoiTFMwdExTMUNSVWRKVGlCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2sxSlNVSnJha05EUVZScFowRjNTVUpCWjBsQ1FWUkJTMEpuWjNGb2EycFBVRkZSUkVGcVFYVk5VbFYzUlhkWlJGWlJVVXRGZDNoNllWZGtlbVJIT1hrS1dsTTFhMXBZV1hoR1ZFRlVRbWRPVmtKQlRWUkVTRTV3V2pOT01HSXpTbXhNV0U0eFdXcEJaVVozTUhsT2FrRXdUVlJWZUU1RVRUUk9SR2hoUm5jd2VRcE9ha0V3VFZSVmVFNVVUVFZPUkdoaFRVRkJkMWRVUVZSQ1oyTnhhR3RxVDFCUlNVSkNaMmR4YUd0cVQxQlJUVUpDZDA1RFFVRlVMM0JKUVdaWldXNUxDazlHYkUxS00zYzBMMnBxUmxoNFRHNHhTRlZOWkVzMGJteDJiU3RLV0c1WmNUbFlPRlZpTkVWRFJFcFFjRUp1VW1sd1pGQkRUWGxYWTBsRGRIRkVPV1lLVlVGdFpIVnZiMUZLWmpReWJ6TlZkMk42UVU5Q1owNVdTRkU0UWtGbU9FVkNRVTFEUWpSQmQwVjNXVVJXVWpCc1FrRjNkME5uV1VsTGQxbENRbEZWU0FwQmQwMTNTSGRaUkZaU01HcENRbWQzUm05QlZXbHFPVEJ5VFZSeVVGaHlkM2hHYm5kTk9FOUdla3MxUW5Ock1IZEdVVmxFVmxJd1VrRlJTQzlDUVhOM0NrTlpSVWhqTTFacFlXMVdhbVJFUVZWQ1oyOXlRbWRGUlVGWlR5OU5RVVZDUWtGYWNHTXpUakZhV0VsM1EyZFpTVXR2V2tsNmFqQkZRWGRKUkZOQlFYY0tVbEZKWjFSSk4ya3pUWEYwVVRBMlp6QnlNbTlEWXpWb1QwZFBWRVZLYlVKSlZUSTVhRXhqVGxKNFJXeHBTbTlEU1ZGRWNuWk9TSE56U21vd1JqWlVNd293UmpaTU4wRkhiWEpDVlhGQllWSllSV0owWVhOaE5IcFJkWHA0YUdjOVBRb3RMUzB0TFVWT1JDQkRSVkpVU1VaSlEwRlVSUzB0TFMwdENnPT0ifX19fQ=="
	integratedTime := int64(1234567890)
	logIndex := int64(42)
	treeSize := int64(100)
	rootHash := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	logID := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	checkpoint := "checkpoint"
	return models.LogEntryAnon{
		Body:           body,
		IntegratedTime: &integratedTime,
		LogIndex:       &logIndex,
		LogID:          &logID,
		Verification: &models.LogEntryAnonVerification{
			SignedEntryTimestamp: []byte("sig"),
			InclusionProof: &models.InclusionProof{
				LogIndex:   &logIndex,
				TreeSize:   &treeSize,
				RootHash:   &rootHash,
				Hashes:     []string{},
				Checkpoint: &checkpoint,
			},
		},
	}
}

func selfSignedCertificate(commonName string, emails []string, uris []string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	var parsedURIs []*url.URL
	for _, u := range uris {
		parsed, _ := url.Parse(u)
		parsedURIs = append(parsedURIs, parsed)
	}

	var subject pkix.Name
	if commonName != "" {
		subject.CommonName = commonName
		subject.Organization = []string{"dev"}
	}

	ct := &x509.Certificate{
		SerialNumber:   big.NewInt(1),
		Subject:        subject,
		EmailAddresses: emails,
		URIs:           parsedURIs,
		NotBefore:      time.Now().Add(-1 * time.Minute),
		NotAfter:       time.Now().Add(24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, ct, ct, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, priv, nil
}
