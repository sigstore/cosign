/*
Copyright The Rekor Authors

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
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/go-openapi/swag"
	"github.com/google/trillian/merkle/logverifier"
	"github.com/google/trillian/merkle/rfc6962/hasher"
	"github.com/pkg/errors"

	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/rekor/cmd/cli/app"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
)

// Verify will verify the signature, public key and payload are in the tlog, as well as verifying the signature itself
// most of this code taken from github.com/sigstore/rekor/cmd/cli/app/verify.go
func Verify(signedPayload []cosign.SignedPayload, publicKey ed25519.PublicKey) error {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})

	if os.Getenv(Env) != "1" {
		return nil
	}
	rekorClient, err := app.GetRekorClient(tlogServer())
	if err != nil {
		return err
	}

	for _, sp := range signedPayload {
		params := entries.NewGetLogEntryProofParams()
		searchParams := entries.NewSearchLogQueryParams()
		searchLogQuery := models.SearchLogQuery{}
		signature, err := base64.StdEncoding.DecodeString(sp.Base64Signature)
		if err != nil {
			return errors.Wrap(err, "decoding base64 signature")
		}
		re := rekorEntry(sp.Payload, signature, pubBytes)
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
			return fmt.Errorf("entry in log cannot be located")
		} else if len(resp.Payload) > 1 {
			return fmt.Errorf("multiple entries returned; this should not happen")
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
	}
	fmt.Println("Verified signature, payload and public key exist in transparency log")
	return nil
}
