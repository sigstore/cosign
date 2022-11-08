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

package bundle

import (
	"github.com/sigstore/rekor/pkg/generated/models"
)

type Bundle struct {
	VerificationData
	VerificationMaterial
}

// VerificationData contains extra data that can be used to verify things
// such as transparency logs and timestamped verifications.
type VerificationData struct {
	// RekorPayload holds metadata about recording a Signature's ephemeral key to
	// a Rekor transparency log.
	// Use Payload instead of TransparencyLogEntry to keep backwards compatibility.
	Payload RekorPayload

	// TimestampVerificationData holds metadata about a timestamped verification.
	TimestampVerificationData
}

// VerificationMaterial captures details on the materials used to verify
// signatures or any additional timestamped verifications.
type VerificationMaterial struct {
	// A chain of X.509 certificates.
	CertBytes []byte

	// PublicKeyIdentifier optional unauthenticated hint on which key to use.
	PublicKeyIdentifier string
}

// TimestampVerificationData contains various timestamped data following RFC3161.
type TimestampVerificationData struct {
	// SignedEntryTimestamp holds metadata about a timestamped counter signature over the artifacts signature.
	SignedEntryTimestamp []byte

	// EntryTimestampAuthority contains the recorded entry from timestamp authority server.
	EntryTimestampAuthority []byte
}

func EntryToBundle(tLogEntry *models.LogEntryAnon, signedEntryTimestamp, entryTimestampAuthority, certBytes []byte, pubKeyID string) *Bundle {
	b := &Bundle{}
	// If none of the verification data is configured then return nil
	if (tLogEntry == nil || tLogEntry.Verification == nil) && len(entryTimestampAuthority) == 0 {
		return nil
	}
	// Add Transparency log entry and a signed timestamp value
	if tLogEntry != nil && tLogEntry.Verification != nil {
		b.Payload = RekorPayload{
			Body:           tLogEntry.Body,
			IntegratedTime: *tLogEntry.IntegratedTime,
			LogIndex:       *tLogEntry.LogIndex,
			LogID:          *tLogEntry.LogID,
		}
		b.SignedEntryTimestamp = tLogEntry.Verification.SignedEntryTimestamp

		if len(signedEntryTimestamp) > 0 {
			b.SignedEntryTimestamp = signedEntryTimestamp
		}
	}
	// Set the EntryTimestampAuthority from the timestamp authority server
	if len(entryTimestampAuthority) > 0 {
		b.EntryTimestampAuthority = entryTimestampAuthority
	}
	if len(certBytes) > 0 || pubKeyID != "" {
		b.CertBytes = certBytes
		b.PublicKeyIdentifier = pubKeyID
	}
	return b
}
