// Copyright 2021 The Sigstore Authors.
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

package rekor

import (
	"crypto"
	"crypto/x509"

	"github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func bundle(entry *models.LogEntryAnon) *oci.Bundle {
	if entry.Verification == nil {
		return nil
	}
	return &oci.Bundle{
		SignedEntryTimestamp: entry.Verification.SignedEntryTimestamp,
		Payload: oci.BundlePayload{
			Body:           entry.Body,
			IntegratedTime: *entry.IntegratedTime,
			LogIndex:       *entry.LogIndex,
			LogID:          *entry.LogID,
		},
	}
}

func rekorBytes(cert *x509.Certificate, pub crypto.PublicKey) ([]byte, error) {
	// Upload the cert or the public key, depending on what we have
	if cert != nil {
		return cryptoutils.MarshalCertificateToPEM(cert)
	}
	return cryptoutils.MarshalPublicKeyToPEM(pub)
}
