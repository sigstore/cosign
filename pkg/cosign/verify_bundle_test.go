//
// Copyright 2025 The Sigstore Authors.
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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sync"
	"testing"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/tlog"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
)

type bundleMutator struct {
	verify.SignedEntity

	eraseTSA  bool
	eraseTlog bool
	eraseSET  bool
}

func (b *bundleMutator) Timestamps() ([][]byte, error) {
	if b.eraseTSA {
		return [][]byte{}, nil
	}
	return b.SignedEntity.Timestamps()
}

func (b *bundleMutator) TlogEntries() ([]*tlog.Entry, error) {
	if b.eraseTlog {
		return []*tlog.Entry{}, nil
	}
	if b.eraseSET {
		var entries []*tlog.Entry
		oldEntries, err := b.SignedEntity.TlogEntries()
		if err != nil {
			return nil, err
		}
		for _, entry := range oldEntries {
			mutEntry, err := tlog.NewEntry([]byte(entry.Body().(string)), entry.IntegratedTime().Unix(), entry.LogIndex(), []byte(entry.LogKeyID()), []byte{}, nil)
			if err != nil {
				return nil, err
			}
			entries = append(entries, mutEntry)
		}
		return entries, nil
	}
	return b.SignedEntity.TlogEntries()
}

func TestVerifyBundle(t *testing.T) {
	virtualSigstore, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)
	virtualSigstore2, err := ca.NewVirtualSigstore() // for testing invalid trusted material
	assert.NoError(t, err)

	artifact := []byte("artifact")
	digest := sha256.Sum256(artifact)
	digestHex := hex.EncodeToString(digest[:])
	statementFmt := `{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://example.com/predicateType","subject":[{"name":"subject","digest":{"sha256":"%s"}}],"predicate":{}}`
	statementCorrect := []byte(fmt.Sprintf(statementFmt, digestHex))

	identity := "foo@example.com"
	issuer := "example issuer"
	standardIdentities := []Identity{
		{
			Issuer:  issuer,
			Subject: identity,
		},
	}

	attestation, err := virtualSigstore.Attest(identity, issuer, statementCorrect)
	if err != nil {
		t.Fatal(err)
	}

	blobSig, err := virtualSigstore.Sign(identity, issuer, artifact)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name                 string
		checkOpts            *CheckOpts
		artifactPolicyOption verify.ArtifactPolicyOption
		entity               verify.SignedEntity
		wantErr              bool
	}{
		{
			name: "valid",
			checkOpts: &CheckOpts{
				Identities:          standardIdentities,
				IgnoreSCT:           true,
				UseSignedTimestamps: true,
				TrustedMaterial:     virtualSigstore,
			},
			artifactPolicyOption: verify.WithArtifact(bytes.NewReader(artifact)),
			entity:               attestation,
			wantErr:              false,
		},
		{
			name: "valid blob signature",
			checkOpts: &CheckOpts{
				Identities:          standardIdentities,
				IgnoreSCT:           true,
				UseSignedTimestamps: true,
				TrustedMaterial:     virtualSigstore,
			},
			artifactPolicyOption: verify.WithArtifact(bytes.NewReader(artifact)),
			entity:               blobSig,
			wantErr:              false,
		},
		{
			name: "invalid, wrong artifact",
			checkOpts: &CheckOpts{
				Identities:          standardIdentities,
				IgnoreSCT:           true,
				UseSignedTimestamps: true,
				TrustedMaterial:     virtualSigstore,
			},
			artifactPolicyOption: verify.WithArtifact(bytes.NewReader([]byte("not the artifact"))),
			entity:               attestation,
			wantErr:              true,
		},
		{
			name: "invalid blob signature, wrong artifact",
			checkOpts: &CheckOpts{
				Identities:          standardIdentities,
				IgnoreSCT:           true,
				UseSignedTimestamps: true,
				TrustedMaterial:     virtualSigstore,
			},
			artifactPolicyOption: verify.WithArtifact(bytes.NewReader([]byte("not the artifact"))),
			entity:               blobSig,
			wantErr:              true,
		},
		{
			name: "valid, pattern match issuer",
			checkOpts: &CheckOpts{
				Identities: []Identity{
					{
						IssuerRegExp: ".*issuer",
						Subject:      "foo@example.com",
					},
				},
				IgnoreSCT:           true,
				UseSignedTimestamps: true,
				TrustedMaterial:     virtualSigstore,
			},
			artifactPolicyOption: verify.WithArtifact(bytes.NewReader(artifact)),
			entity:               attestation,
			wantErr:              false,
		},
		{
			name: "valid, pattern match subject",
			checkOpts: &CheckOpts{
				Identities: []Identity{
					{
						Issuer:        "example issuer",
						SubjectRegExp: ".*@example.com",
					},
				},
				IgnoreSCT:           true,
				UseSignedTimestamps: true,
				TrustedMaterial:     virtualSigstore,
			},
			artifactPolicyOption: verify.WithArtifact(bytes.NewReader(artifact)),
			entity:               attestation,
			wantErr:              false,
		},
		{
			name: "invalid, pattern match issuer",
			checkOpts: &CheckOpts{
				Identities: []Identity{
					{
						IssuerRegExp: ".* not my issuer",
						Subject:      "foo@example.com",
					},
				},
				IgnoreSCT:           true,
				UseSignedTimestamps: true,
				TrustedMaterial:     virtualSigstore,
			},
			artifactPolicyOption: verify.WithArtifact(bytes.NewReader(artifact)),
			entity:               attestation,
			wantErr:              true,
		},
		{
			name: "invalid, pattern match subject",
			checkOpts: &CheckOpts{
				Identities: []Identity{
					{
						Issuer:        "example issuer",
						SubjectRegExp: ".*@otherexample.com",
					},
				},
				IgnoreSCT:           true,
				UseSignedTimestamps: true,
				TrustedMaterial:     virtualSigstore,
			},
			artifactPolicyOption: verify.WithArtifact(bytes.NewReader(artifact)),
			entity:               attestation,
			wantErr:              true,
		},
		{
			name: "invalid trusted material",
			checkOpts: &CheckOpts{
				Identities:      standardIdentities,
				IgnoreSCT:       true,
				TrustedMaterial: virtualSigstore2,
			},
			artifactPolicyOption: verify.WithArtifact(bytes.NewReader(artifact)),
			entity:               attestation,
			wantErr:              true,
		},
		{
			name: "do not require tlog, missing tlog",
			checkOpts: &CheckOpts{
				Identities:          standardIdentities,
				IgnoreSCT:           true,
				IgnoreTlog:          true,
				UseSignedTimestamps: true,
				TrustedMaterial:     virtualSigstore,
			},
			artifactPolicyOption: verify.WithArtifact(bytes.NewReader(artifact)),
			entity:               &bundleMutator{SignedEntity: attestation, eraseTlog: true},
			wantErr:              false,
		},
		{
			name: "do not require tsa, missing tsa",
			checkOpts: &CheckOpts{
				Identities:          standardIdentities,
				IgnoreSCT:           true,
				IgnoreTlog:          false,
				UseSignedTimestamps: false,
				TrustedMaterial:     virtualSigstore,
			},
			artifactPolicyOption: verify.WithArtifact(bytes.NewReader(artifact)),
			entity:               &bundleMutator{SignedEntity: attestation, eraseTSA: true},
			wantErr:              false,
		},
		{
			name: "require tlog, missing tlog",
			checkOpts: &CheckOpts{
				Identities:          standardIdentities,
				IgnoreSCT:           true,
				UseSignedTimestamps: true,
				TrustedMaterial:     virtualSigstore,
			},
			artifactPolicyOption: verify.WithArtifact(bytes.NewReader(artifact)),
			entity:               &bundleMutator{SignedEntity: attestation, eraseTlog: true},
			wantErr:              true,
		},
		{
			name: "require SET, missing set",
			checkOpts: &CheckOpts{
				Identities:          standardIdentities,
				IgnoreSCT:           true,
				IgnoreTlog:          false,
				UseSignedTimestamps: false, // both set to false requires an SET
				TrustedMaterial:     virtualSigstore,
			},
			artifactPolicyOption: verify.WithArtifact(bytes.NewReader(artifact)),
			entity:               &bundleMutator{SignedEntity: attestation, eraseSET: true},
			wantErr:              true,
		},
		{
			name: "require tsa, missing tsa",
			checkOpts: &CheckOpts{
				Identities:          standardIdentities,
				IgnoreSCT:           true,
				UseSignedTimestamps: true,
				TrustedMaterial:     virtualSigstore,
			},
			artifactPolicyOption: verify.WithArtifact(bytes.NewReader(artifact)),
			entity:               &bundleMutator{SignedEntity: attestation, eraseTSA: true},
			wantErr:              true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err = VerifyNewBundle(context.Background(), tc.checkOpts, tc.artifactPolicyOption, tc.entity)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestVerifyBundleWithSigVerifier(t *testing.T) {
	virtualSigstore, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	artifact := []byte("artifact")
	digest := sha256.Sum256(artifact)

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)

	sv, err := signature.LoadECDSASignerVerifier(privKey, crypto.SHA256)
	assert.NoError(t, err)

	sig, err := sv.SignMessage(bytes.NewReader(artifact))
	assert.NoError(t, err)
	assert.NotNil(t, sig)

	ts, err := virtualSigstore.TimestampResponse(sig)
	assert.NoError(t, err)

	b, err := sgbundle.NewBundle(&protobundle.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle+json;version=0.3",
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_PublicKey{
				PublicKey: &protocommon.PublicKeyIdentifier{
					Hint: "",
				},
			},
			TimestampVerificationData: &protobundle.TimestampVerificationData{
				Rfc3161Timestamps: []*protocommon.RFC3161SignedTimestamp{{SignedTimestamp: ts}},
			},
		},
		Content: &protobundle.Bundle_MessageSignature{
			MessageSignature: &protocommon.MessageSignature{
				MessageDigest: &protocommon.HashOutput{
					Algorithm: protocommon.HashAlgorithm_SHA2_256,
					Digest:    digest[:],
				},
				Signature: sig,
			},
		},
	})
	assert.NoError(t, err)
	assert.NotNil(t, b)

	for _, tc := range []struct {
		name                 string
		checkOpts            *CheckOpts
		artifactPolicyOption verify.ArtifactPolicyOption
		entity               verify.SignedEntity
		wantErr              bool
	}{
		{
			name: "valid",
			checkOpts: &CheckOpts{
				UseSignedTimestamps: true,
				IgnoreTlog:          true,
				TrustedMaterial:     virtualSigstore,
				SigVerifier:         sv,
			},
			artifactPolicyOption: verify.WithArtifact(bytes.NewReader(artifact)),
			entity:               b,
			wantErr:              false,
		},
		{
			name: "invalid, wrong artifact",
			checkOpts: &CheckOpts{
				UseSignedTimestamps: true,
				IgnoreTlog:          true,
				TrustedMaterial:     virtualSigstore,
				SigVerifier:         sv,
			},
			artifactPolicyOption: verify.WithArtifact(bytes.NewReader([]byte("wrong artifact"))),
			entity:               b,
			wantErr:              true,
		},
		{
			name: "invalid, sigverifier not set",
			checkOpts: &CheckOpts{
				UseSignedTimestamps: true,
				IgnoreTlog:          true,
				TrustedMaterial:     virtualSigstore,
			},
			artifactPolicyOption: verify.WithArtifact(bytes.NewReader([]byte("wrong artifact"))),
			entity:               b,
			wantErr:              true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err = VerifyNewBundle(context.Background(), tc.checkOpts, tc.artifactPolicyOption, tc.entity)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

type mockSignedEntity struct {
	verify.SignedEntity
	tlogEntries []*tlog.Entry
}

func (m *mockSignedEntity) TlogEntries() ([]*tlog.Entry, error) {
	return m.tlogEntries, nil
}

type mockVerifierForBundle struct{}

func (m *mockVerifierForBundle) PublicKey(_ ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return nil, nil
}

func (m *mockVerifierForBundle) VerifySignature(_, _ io.Reader, _ ...signature.VerifyOption) error {
	return nil
}

func makeTlogEntry(t *testing.T, integratedTime int64) *tlog.Entry {
	body := []byte(`{}`)
	tle := &v1.TransparencyLogEntry{
		LogIndex: 1,
		LogId: &protocommon.LogId{
			KeyId: []byte("ignored"),
		},
		KindVersion: &v1.KindVersion{
			Kind:    "ignored",
			Version: "ignored",
		},
		IntegratedTime:    integratedTime,
		CanonicalizedBody: body,
	}
	entry, err := tlog.NewTlogEntry(tle)
	if err != nil {
		t.Fatal(err)
	}
	return entry
}

// rekorV2Entity wraps a real SignedEntity but reports caller-supplied tlog
// entries, letting a test force the Rekor v2 code path (an entry with no
// integrated time) that makes rekorV2Bundle write co.UseSignedTimestamps.
type rekorV2Entity struct {
	verify.SignedEntity
	entries []*tlog.Entry
}

func (e *rekorV2Entity) TlogEntries() ([]*tlog.Entry, error) {
	return e.entries, nil
}

// TestVerifyNewBundleConcurrentNoDataRace guards against the data race where the
// attestation verification fan-out shares one *CheckOpts across goroutines:
// VerifyNewBundle -> rekorV2Bundle writes co.UseSignedTimestamps for a Rekor v2
// bundle while sibling goroutines read it in co.verificationOptions(). Run with
// -race; without VerifyNewBundle copying co, the detector fires.
func TestVerifyNewBundleConcurrentNoDataRace(t *testing.T) {
	virtualSigstore, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}

	artifact := []byte("artifact")
	digest := sha256.Sum256(artifact)
	digestHex := hex.EncodeToString(digest[:])
	statement := []byte(fmt.Sprintf(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://example.com/predicateType","subject":[{"name":"subject","digest":{"sha256":"%s"}}],"predicate":{}}`, digestHex))
	attestation, err := virtualSigstore.Attest("foo@example.com", "example issuer", statement)
	if err != nil {
		t.Fatal(err)
	}

	// Report a single Rekor v2 entry (zero integrated time, no v1 entry) so
	// rekorV2Bundle sets co.UseSignedTimestamps during verification.
	bundle := &rekorV2Entity{SignedEntity: attestation, entries: []*tlog.Entry{makeTlogEntry(t, 0)}}

	// One *CheckOpts shared across goroutines, exactly as verifyImageAttestationsSigstoreBundle shares it.
	co := &CheckOpts{
		Identities:      []Identity{{Issuer: "example issuer", Subject: "foo@example.com"}},
		IgnoreSCT:       true,
		TrustedMaterial: virtualSigstore,
	}
	artifactPolicyOption := verify.WithArtifact(bytes.NewReader(artifact))

	const goroutines = 50
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			<-start // release all goroutines together to widen the race window
			// Verification against the synthetic tlog entry is expected to fail;
			// the test only asserts the concurrent calls don't race on co.
			_, _ = VerifyNewBundle(context.Background(), co, artifactPolicyOption, bundle)
		}()
	}
	close(start)
	wg.Wait()
}

func TestRekorV2Bundle(t *testing.T) {
	rekorV1Entry := makeTlogEntry(t, 1234567890)
	rekorV2Entry := makeTlogEntry(t, 0)

	tests := []struct {
		name                        string
		co                          *CheckOpts
		entries                     []*tlog.Entry
		expectedUseSignedTimestamps bool
	}{
		{
			name: "IgnoreTlog true",
			co: &CheckOpts{
				IgnoreTlog: true,
			},
			entries:                     []*tlog.Entry{rekorV2Entry},
			expectedUseSignedTimestamps: false,
		},
		{
			name: "SigVerifier set",
			co: &CheckOpts{
				SigVerifier: &mockVerifierForBundle{},
			},
			entries:                     []*tlog.Entry{rekorV2Entry},
			expectedUseSignedTimestamps: false,
		},
		{
			name:                        "Rekor v1 entry",
			co:                          &CheckOpts{},
			entries:                     []*tlog.Entry{rekorV1Entry},
			expectedUseSignedTimestamps: false,
		},
		{
			name:                        "Rekor v2 entry",
			co:                          &CheckOpts{},
			entries:                     []*tlog.Entry{rekorV2Entry},
			expectedUseSignedTimestamps: true,
		},
		{
			name:                        "Mixed entries",
			co:                          &CheckOpts{},
			entries:                     []*tlog.Entry{rekorV1Entry, rekorV2Entry},
			expectedUseSignedTimestamps: false,
		},
		{
			name: "Already set with Rekor v1",
			co: &CheckOpts{
				UseSignedTimestamps: true,
			},
			entries:                     []*tlog.Entry{rekorV1Entry},
			expectedUseSignedTimestamps: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bundle := &mockSignedEntity{tlogEntries: tc.entries}
			err := rekorV2Bundle(bundle, tc.co)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedUseSignedTimestamps, tc.co.UseSignedTimestamps)
		})
	}
}
