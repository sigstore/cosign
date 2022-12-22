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

package cosign

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"testing"

	ttestdata "github.com/google/certificate-transparency-go/trillian/testdata"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/tuf"
)

var (
	demoLogID = [32]byte{19, 56, 222, 93, 229, 36, 102, 128, 227, 214, 3, 121, 93, 175, 126, 236, 97, 217, 34, 32, 40, 233, 98, 27, 46, 179, 164, 251, 84, 10, 60, 57}
)

func TestGetRekorPubKeys(t *testing.T) {
	keys, err := GetRekorPubs(context.Background())
	if err != nil {
		t.Errorf("Unexpected error calling GetRekorPubs, expected nil: %v", err)
	}
	if len(keys.Keys) == 0 {
		t.Errorf("expected 1 or more keys, got 0")
	}
	// check that the mapping of key digest to key is correct
	for logID, key := range keys.Keys {
		expectedLogID, err := GetTransparencyLogID(key.PubKey)
		if err != nil {
			t.Fatalf("unexpected error generated log ID: %v", err)
		}
		if logID != expectedLogID {
			t.Fatalf("key digests are not equal")
		}
	}
}

func TestExpectedRekorResponse(t *testing.T) {
	validUUID := "f794467401d57241b7903737211c721cb3315648d077a9f02ceefb6e404a05de"
	validUUID1 := "7794467401d57241b7903737211c721cb3315648d077a9f02ceefb6e404a05de"

	validTreeID := "0FFFFFFFFFFFFFFF"
	validTreeID1 := "3315648d077a9f02"
	invalidTreeID := "0000000000000000"
	tests := []struct {
		name         string
		requestUUID  string
		responseUUID string
		treeID       string
		wantErr      bool
	}{
		{
			name:         "valid match with request & response entry UUID",
			requestUUID:  validTreeID + validUUID,
			responseUUID: validTreeID + validUUID,
			treeID:       validTreeID,
			wantErr:      false,
		},
		// The following is the current typical Rekor behavior.
		{
			name:         "valid match with request entry UUID",
			requestUUID:  validTreeID + validUUID,
			responseUUID: validUUID,
			treeID:       validTreeID,
			wantErr:      false,
		},
		{
			name:         "valid match with request UUID",
			requestUUID:  validUUID,
			responseUUID: validUUID,
			treeID:       validTreeID,
			wantErr:      false,
		},
		{
			name:         "valid match with response entry UUID",
			requestUUID:  validUUID,
			responseUUID: validTreeID + validUUID,
			treeID:       validTreeID,
			wantErr:      false,
		},
		{
			name:         "mismatch uuid with response tree id",
			requestUUID:  validUUID,
			responseUUID: validTreeID + validUUID1,
			treeID:       validTreeID,
			wantErr:      true,
		},
		{
			name:         "mismatch uuid with request tree id",
			requestUUID:  validTreeID + validUUID1,
			responseUUID: validUUID,
			treeID:       validTreeID,
			wantErr:      true,
		},
		{
			name:         "mismatch tree id",
			requestUUID:  validTreeID + validUUID,
			responseUUID: validUUID,
			treeID:       validTreeID1,
			wantErr:      true,
		},
		{
			name:         "invalid response tree id",
			requestUUID:  validTreeID + validUUID,
			responseUUID: invalidTreeID + validUUID,
			treeID:       invalidTreeID,
			wantErr:      true,
		},
		{
			name:         "invalid request tree id",
			requestUUID:  invalidTreeID + validUUID,
			responseUUID: validUUID,
			treeID:       invalidTreeID,
			wantErr:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isExpectedResponseUUID(tt.requestUUID,
				tt.responseUUID, tt.treeID); (got != nil) != tt.wantErr {
				t.Errorf("isExpectedResponseUUID() = %v, want %v", got, tt.wantErr)
			}
		})
	}
}

func TestGetCTLogID(t *testing.T) {
	block, _ := pem.Decode([]byte(ttestdata.DemoPublicKey))
	pk, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("unexpected error loading public key: %v", err)
	}

	got, err := GetTransparencyLogID(pk)
	if err != nil {
		t.Fatalf("error getting logid: %v", err)
	}

	if want := hex.EncodeToString(demoLogID[:]); got != want {
		t.Errorf("logID: \n%v want \n%v", got, want)
	}
}

func TestVerifyTLogEntryOfflineFailsWithInvalidPublicKey(t *testing.T) {
	// Then try to validate with keys that are not ecdsa.PublicKey and should
	// fail.
	var rsaPrivKey crypto.PrivateKey
	rsaPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("Unable to create RSA test key: %v", err)
	}
	var signer crypto.Signer
	var ok bool
	if signer, ok = rsaPrivKey.(crypto.Signer); !ok {
		t.Fatalf("Unable to create signer out of RSA test key: %v", err)
	}
	rsaPEM, err := cryptoutils.MarshalPublicKeyToPEM(signer.Public())
	if err != nil {
		t.Fatalf("Unable to marshal RSA test key: %v", err)
	}
	rekorPubKeys := NewTrustedTransparencyLogPubKeys()
	if err = rekorPubKeys.AddTransparencyLogPubKey(rsaPEM, tuf.Active); err != nil {
		t.Fatalf("failed to add RSA key to transparency log public keys: %v", err)
	}

	err = VerifyTLogEntryOffline(&models.LogEntryAnon{Verification: &models.LogEntryAnonVerification{InclusionProof: &models.InclusionProof{}}}, &rekorPubKeys)
	if err == nil {
		t.Fatal("Wanted error got none")
	}
	if !strings.Contains(err.Error(), "is not type ecdsa.PublicKey") {
		t.Fatalf("Did not get expected error message, wanted 'is not type ecdsa.PublicKey' got: %v", err)
	}
}
