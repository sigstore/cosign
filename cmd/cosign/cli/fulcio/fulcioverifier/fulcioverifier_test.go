// Copyright 2025 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package fulcioverifier

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/trillian/ctfe"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	ctx509util "github.com/google/certificate-transparency-go/x509util"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/initialize"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/fulcio/pkg/ctl"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func TestNewSigner(t *testing.T) {
	td := t.TempDir()
	t.Setenv("TUF_ROOT", td)
	tufRepo := t.TempDir()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	skid, err := cryptoutils.SKID(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert := createBaseCert(t, privateKey, skid, big.NewInt(1))
	logID, err := ctfe.GetCTLogID(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sct := ct.SignedCertificateTimestamp{
		SCTVersion: ct.V1,
		Timestamp:  12345,
		LogID:      ct.LogID{KeyID: logID},
	}
	preCert := createBaseCert(t, privateKey, skid, big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})
	err = newTUF(tufRepo, map[string][]byte{"ctfe.pub": pubPEM})
	if err != nil {
		t.Fatal(err)
	}
	tufServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.FileServer(http.Dir(tufRepo)).ServeHTTP(w, r)
	}))
	err = initialize.DoInitialize(context.Background(), filepath.Join(tufRepo, "1.root.json"), tufServer.URL)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name            string
		embeddedSCT     bool
		trustedMaterial root.TrustedMaterial
	}{
		{
			name:            "detached SCT",
			embeddedSCT:     false,
			trustedMaterial: nil,
		},
		{
			name:            "embedded SCT with legacy TUF metadata",
			embeddedSCT:     true,
			trustedMaterial: nil,
		},
		{
			name:        "embedded SCT with trusted root",
			embeddedSCT: true,
			trustedMaterial: &fakeTrustedMaterial{
				transparencyLog: map[string]*root.TransparencyLog{
					hex.EncodeToString(logID[:]): {
						PublicKey: &privateKey.PublicKey,
					},
				},
				cas: []root.CertificateAuthority{
					&root.FulcioCertificateAuthority{
						Root: caCert,
					},
				},
			},
		},
		{
			name:        "detached SCT with trusted root uses legacy TUF client",
			embeddedSCT: false,
			trustedMaterial: &fakeTrustedMaterial{
				transparencyLog: map[string]*root.TransparencyLog{
					hex.EncodeToString(logID[:]): {
						PublicKey: &privateKey.PublicKey,
					},
				},
				cas: []root.CertificateAuthority{
					&root.FulcioCertificateAuthority{
						Root: caCert,
					},
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			leafCert := preCert
			sctHeader := ""
			if test.embeddedSCT {
				leafCert = embedSCT(t, privateKey, skid, preCert, sct)
			} else {
				sctHeader = detachedSCT(t, privateKey, preCert, sct)
			}
			pemChain, _ := cryptoutils.MarshalCertificatesToPEM([]*x509.Certificate{leafCert, caCert})
			testServer := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, _ *http.Request) {
					if sctHeader != "" {
						w.Header().Set("SCT", sctHeader)
					}
					w.WriteHeader(http.StatusCreated)
					_, _ = w.Write(pemChain)
				}))
			defer testServer.Close()

			ctx := context.Background()
			ko := options.KeyOpts{
				OIDCDisableProviders: true,
				// Generated from https://justtrustme.dev/token?sub=test-subject
				IDToken:        "eyJhbGciOiJSUzI1NiIsImtpZCI6ImFhOWE1YjA5LTExMzktNGU2YS1hNjMxLTA2ZTU3NDU4NzI0MSJ9.eyJleHAiOjE3NTQwMjgzODMsImlhdCI6MTc1NDAyNjU4MywiaXNzIjoiaHR0cHM6Ly9qdXN0dHJ1c3RtZS5kZXYiLCJzdWIiOiJ0ZXN0LXN1YmplY3QifQ.lfLAxD5XnbtvmGbgJTTV8nLDxUk9_KemdFG3_HydIWwLdKR86KYwwJn_5ONdycVuNluLOx96xA6jc4m1CjzH9N5Dafw4MQpjzXJWFlhM9sehW8VU_TzH1lEfY3KTxwDBRkZnVGXr3bJGowfdTyWLJxgl16nVTqsRAqIsTE4SEVHscDP1r5T0_B7RQ4Sjih1Z7zlIYzXxpAiVCOZ321Gqgxtej_xPfZ9rk1Z5-Uw-8sc6spog8Uca3kqumncPgM0su1ww5bWmawb4msqUnoOcPCPo-oywC-gdssWt_HmFPRhvREvdv5eYNDfp1bjS-nWAGJN7a4iO9qGBJed7zI6JNA",
				FulcioURL:      testServer.URL,
				FulcioAuthFlow: "token",
			}
			privKey, err := cosign.GeneratePrivateKey()
			if err != nil {
				t.Fatal(err)
			}
			sv, err := signature.LoadECDSASignerVerifier(privKey, crypto.SHA256)
			if err != nil {
				t.Fatal(err)
			}

			fs, err := NewSigner(ctx, ko, sv)
			if err != nil {
				t.Fatal(err)
			}
			if test.embeddedSCT {
				assert.Empty(t, fs.SCT)
			} else {
				assert.NotEmpty(t, fs.SCT)
			}
		})
	}
}

func getSCT(t *testing.T, privateKey *rsa.PrivateKey, preCert *x509.Certificate, sctInput ct.SignedCertificateTimestamp, embedded bool) ct.SignedCertificateTimestamp {
	logEntry := ct.LogEntry{
		Leaf: ct.MerkleTreeLeaf{
			Version:  ct.V1,
			LeafType: ct.TimestampedEntryLeafType,
			TimestampedEntry: &ct.TimestampedEntry{
				Timestamp: sctInput.Timestamp,
			},
		},
	}
	if embedded {
		logEntry.Leaf.TimestampedEntry.EntryType = ct.PrecertLogEntryType
		logEntry.Leaf.TimestampedEntry.PrecertEntry = &ct.PreCert{
			IssuerKeyHash:  sha256.Sum256(preCert.RawSubjectPublicKeyInfo),
			TBSCertificate: preCert.RawTBSCertificate,
		}
	} else {
		logEntry.Leaf.TimestampedEntry.EntryType = ct.X509LogEntryType
		logEntry.Leaf.TimestampedEntry.X509Entry = &ct.ASN1Cert{Data: preCert.Raw}
	}
	data, err := ct.SerializeSCTSignatureInput(sctInput, logEntry)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(data)
	signature, err := privateKey.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	sct := ct.SignedCertificateTimestamp{
		SCTVersion: sctInput.SCTVersion,
		LogID:      sctInput.LogID,
		Timestamp:  sctInput.Timestamp,
		Signature: ct.DigitallySigned{
			Algorithm: tls.SignatureAndHashAlgorithm{
				Hash:      tls.SHA256,
				Signature: tls.RSA,
			},
			Signature: signature,
		},
	}
	return sct
}

func detachedSCT(t *testing.T, privateKey *rsa.PrivateKey, preCert *x509.Certificate, sctInput ct.SignedCertificateTimestamp) string {
	sct := getSCT(t, privateKey, preCert, sctInput, false)
	addChainResp, err := ctl.ToAddChainResponse(&sct)
	if err != nil {
		t.Fatal(err)
	}
	sctBytes, err := json.Marshal(addChainResp)
	if err != nil {
		t.Fatal(err)
	}

	return base64.StdEncoding.EncodeToString(sctBytes)
}

func embedSCT(t *testing.T, privateKey *rsa.PrivateKey, skid []byte, preCert *x509.Certificate, sctInput ct.SignedCertificateTimestamp) *x509.Certificate {
	sct := getSCT(t, privateKey, preCert, sctInput, true)
	sctList, err := ctx509util.MarshalSCTsIntoSCTList([]*ct.SignedCertificateTimestamp{&sct})
	if err != nil {
		t.Fatal(err)
	}
	sctBytes, err := tls.Marshal(*sctList)
	if err != nil {
		t.Fatal(err)
	}
	asnSCT, err := asn1.Marshal(sctBytes)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		SerialNumber: preCert.SerialNumber,
		SubjectKeyId: skid,
		ExtraExtensions: []pkix.Extension{
			{
				Id:    asn1.ObjectIdentifier(ctx509.OIDExtensionCTSCT),
				Value: asnSCT,
			},
		},
	}
	certDERBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	parsedCert, err := x509.ParseCertificate(certDERBytes)
	if err != nil {
		t.Fatal(err)
	}
	return parsedCert
}

func newKey() (*metadata.Key, signature.Signer, error) {
	pub, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, err
	}
	public, err := metadata.KeyFromPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}
	signer, err := signature.LoadSigner(private, crypto.Hash(0))
	if err != nil {
		return nil, nil, err
	}
	return public, signer, nil
}

func newTUF(td string, targetList map[string][]byte) error {
	expiration := time.Now().AddDate(0, 0, 1).UTC()
	targets := metadata.Targets(expiration)
	targetsDir := filepath.Join(td, "targets")
	err := os.Mkdir(targetsDir, 0700)
	if err != nil {
		return err
	}
	for name, content := range targetList {
		targetPath := filepath.Join(targetsDir, name)
		err := os.WriteFile(targetPath, content, 0600)
		if err != nil {
			return err
		}
		targetFileInfo, err := metadata.TargetFile().FromFile(targetPath, "sha256")
		if err != nil {
			return err
		}
		targets.Signed.Targets[name] = targetFileInfo
	}
	snapshot := metadata.Snapshot(expiration)
	timestamp := metadata.Timestamp(expiration)
	root := metadata.Root(expiration)
	root.Signed.ConsistentSnapshot = false
	public, signer, err := newKey()
	if err != nil {
		return err
	}
	for _, name := range []string{"targets", "snapshot", "timestamp", "root"} {
		err := root.Signed.AddKey(public, name)
		if err != nil {
			return err
		}
		switch name {
		case "targets":
			_, err = targets.Sign(signer)
		case "snapshot":
			_, err = snapshot.Sign(signer)
		case "timestamp":
			_, err = timestamp.Sign(signer)
		case "root":
			_, err = root.Sign(signer)
		}
		if err != nil {
			return err
		}
	}
	err = targets.ToFile(filepath.Join(td, "targets.json"), false)
	if err != nil {
		return err
	}
	err = snapshot.ToFile(filepath.Join(td, "snapshot.json"), false)
	if err != nil {
		return err
	}
	err = timestamp.ToFile(filepath.Join(td, "timestamp.json"), false)
	if err != nil {
		return err
	}
	err = root.ToFile(filepath.Join(td, "1.root.json"), false)
	if err != nil {
		return err
	}
	err = root.VerifyDelegate("root", root)
	if err != nil {
		return err
	}
	err = root.VerifyDelegate("targets", targets)
	if err != nil {
		return err
	}
	err = root.VerifyDelegate("snapshot", snapshot)
	if err != nil {
		return err
	}
	err = root.VerifyDelegate("timestamp", timestamp)
	return err
}

func createBaseCert(t *testing.T, privateKey *rsa.PrivateKey, skid []byte, serialNumber *big.Int) *x509.Certificate {
	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		SubjectKeyId: skid,
	}
	certDERBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	parsedCert, err := x509.ParseCertificate(certDERBytes)
	if err != nil {
		t.Fatal(err)
	}
	return parsedCert
}

type fakeTrustedMaterial struct {
	transparencyLog map[string]*root.TransparencyLog
	cas             []root.CertificateAuthority
}

func (t *fakeTrustedMaterial) CTLogs() map[string]*root.TransparencyLog {
	return t.transparencyLog
}

func (t *fakeTrustedMaterial) FulcioCertificateAuthorities() []root.CertificateAuthority {
	return t.cas
}

func (t *fakeTrustedMaterial) TimestampingAuthorities() []root.TimestampingAuthority {
	panic("not implemented")
}
func (t *fakeTrustedMaterial) RekorLogs() map[string]*root.TransparencyLog { panic("not implemented") }
func (t *fakeTrustedMaterial) PublicKeyVerifier(string) (root.TimeConstrainedVerifier, error) {
	panic("not implemented")
}
