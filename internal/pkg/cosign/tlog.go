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

package cosign

import (
	"context"
	"fmt"
	"os"

	cosignv1 "github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/oci"
	rekPkgClient "github.com/sigstore/rekor/pkg/client"
	rekGenClient "github.com/sigstore/rekor/pkg/generated/client"
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

type tlogUploadFn func(*rekGenClient.Rekor, []byte) (*models.LogEntryAnon, error)

func uploadToTlog(rekorBytes []byte, rekorURL string, upload tlogUploadFn) (*oci.Bundle, error) {
	rekorClient, err := rekPkgClient.GetRekorClient(rekorURL)
	if err != nil {
		return nil, err
	}
	entry, err := upload(rekorClient, rekorBytes)
	if err != nil {
		return nil, err
	}
	fmt.Fprintln(os.Stderr, "tlog entry created with index:", *entry.LogIndex)
	return bundle(entry), nil
}

// RekorSignerWrapper implements `Signer`
type RekorSignerWrapper struct {
	Inner Signer

	RekorURL string
}

// Sign calls a wrapped, inner signer then uploads either the Cert or Pub(licKey) of the results to Rekor, then adds the resulting `Bundle`
func (rs *RekorSignerWrapper) Sign(ctx context.Context, req *SigningRequest) (*SigningResults, error) {
	results, err := rs.Inner.Sign(ctx, req)
	if err != nil {
		return nil, err
	}

	// Upload the cert or the public key, depending on what we have
	rekorBytes := results.Cert
	if rekorBytes == nil {
		rekorBytes, err = cryptoutils.MarshalPublicKeyToPEM(results.Pub)
		if err != nil {
			return nil, err
		}
	}

	bundle, err := uploadToTlog(rekorBytes, rs.RekorURL, func(r *rekGenClient.Rekor, b []byte) (*models.LogEntryAnon, error) {
		return cosignv1.TLogUpload(ctx, r, results.Signature, results.SignedPayload, b)
	})
	if err != nil {
		return nil, err
	}

	results.Bundle = bundle
	return results, nil
}
