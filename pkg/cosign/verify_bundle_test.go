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

package cosign_test

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
	"testing"

	"github.com/sigstore/cosign/v2/pkg/cosign"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
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
	standardIdentities := []cosign.Identity{
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
		checkOpts            *cosign.CheckOpts
		artifactPolicyOption verify.ArtifactPolicyOption
		entity               verify.SignedEntity
		wantErr              bool
	}{
		{
			name: "valid",
			checkOpts: &cosign.CheckOpts{
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
			checkOpts: &cosign.CheckOpts{
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
			checkOpts: &cosign.CheckOpts{
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
			checkOpts: &cosign.CheckOpts{
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
			checkOpts: &cosign.CheckOpts{
				Identities: []cosign.Identity{
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
			checkOpts: &cosign.CheckOpts{
				Identities: []cosign.Identity{
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
			checkOpts: &cosign.CheckOpts{
				Identities: []cosign.Identity{
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
			checkOpts: &cosign.CheckOpts{
				Identities: []cosign.Identity{
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
			checkOpts: &cosign.CheckOpts{
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
			checkOpts: &cosign.CheckOpts{
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
			checkOpts: &cosign.CheckOpts{
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
			checkOpts: &cosign.CheckOpts{
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
			checkOpts: &cosign.CheckOpts{
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
			checkOpts: &cosign.CheckOpts{
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
			_, err = cosign.VerifyNewBundle(context.Background(), tc.checkOpts, tc.artifactPolicyOption, tc.entity)
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
		checkOpts            *cosign.CheckOpts
		artifactPolicyOption verify.ArtifactPolicyOption
		entity               verify.SignedEntity
		wantErr              bool
	}{
		{
			name: "valid",
			checkOpts: &cosign.CheckOpts{
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
			checkOpts: &cosign.CheckOpts{
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
			checkOpts: &cosign.CheckOpts{
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
			_, err = cosign.VerifyNewBundle(context.Background(), tc.checkOpts, tc.artifactPolicyOption, tc.entity)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
