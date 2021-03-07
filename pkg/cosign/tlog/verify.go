/*
Copyright The Sigstore Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package tlog

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/go-openapi/swag"
	"github.com/google/trillian/merkle/logverifier"
	"github.com/google/trillian/merkle/rfc6962/hasher"
	"github.com/pkg/errors"

	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/rekor/cmd/cli/app"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
)

// Verify will verify the signature, public key and payload are in the tlog, as well as verifying the signature itself
// most of this code taken from github.com/sigstore/rekor/cmd/cli/app/verify.go
func Verify(signedPayload []cosign.SignedPayload, publicKey *ecdsa.PublicKey) ([]cosign.SignedPayload, error) {
	wrappedKey, err := cosign.MarshalPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	rekorClient, err := app.GetRekorClient(tlogServer())
	if err != nil {
		return nil, err
	}

	verifyErrs := []string{}
	verifiedPayloads := []cosign.SignedPayload{}

	for _, sp := range signedPayload {
		if err := findEntry(rekorClient, sp, wrappedKey); err != nil {
			verifyErrs = append(verifyErrs, err.Error())
			continue
		}
		verifiedPayloads = append(verifiedPayloads, sp)
	}
	if len(verifiedPayloads) == 0 {
		return nil, fmt.Errorf("no entries found in log:\n%s", strings.Join(verifyErrs, "\n  "))
	}
	return verifiedPayloads, nil
}

func findEntry(rekorClient *client.Rekor, sp cosign.SignedPayload, pubKey []byte) error {
	params := entries.NewGetLogEntryProofParams()
	searchParams := entries.NewSearchLogQueryParams()
	searchLogQuery := models.SearchLogQuery{}
	signature, err := base64.StdEncoding.DecodeString(sp.Base64Signature)
	if err != nil {
		return errors.Wrap(err, "decoding base64 signature")
	}
	re := rekorEntry(sp.Payload, signature, pubKey)
	entry := &models.Rekord{
		APIVersion: swag.String(re.APIVersion()),
		Spec:       re.RekordObj,
	}

	entries := []models.ProposedEntry{entry}
	searchLogQuery.SetEntries(entries)

	searchParams.SetEntry(&searchLogQuery)
	resp, err := rekorClient.Entries.SearchLogQuery(searchParams)
	if err != nil {
		return errors.Wrap(err, "searching log query")
	}
	if len(resp.Payload) == 0 {
		return errors.New("entry not found")
	} else if len(resp.Payload) > 1 {
		return errors.New("multiple entries returned; this should not happen")
	}
	logEntry := resp.Payload[0]
	if len(logEntry) != 1 {
		return errors.New("UUID value can not be extracted")
	}
	for k := range logEntry {
		params.EntryUUID = k
	}
	lep, err := rekorClient.Entries.GetLogEntryProof(params)
	if err != nil {
		return err
	}

	hashes := [][]byte{}
	for _, h := range lep.Payload.Hashes {
		hb, _ := hex.DecodeString(h)
		hashes = append(hashes, hb)
	}

	rootHash, _ := hex.DecodeString(*lep.Payload.RootHash)
	leafHash, _ := hex.DecodeString(params.EntryUUID)

	v := logverifier.New(hasher.DefaultHasher)
	if err := v.VerifyInclusionProof(*lep.Payload.LogIndex, *lep.Payload.TreeSize, hashes, rootHash, leafHash); err != nil {
		return errors.Wrap(err, "verifying inclusion proof")
	}
	return nil
}
