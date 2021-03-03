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
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/google/trillian/merkle/logverifier"
	"github.com/google/trillian/merkle/rfc6962"
	"github.com/pkg/errors"

	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/rekor/cmd/cli/app"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	rekord_v001 "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
)

const (
	tlogEnv       = "TLOG"
	tlogServerEnv = "TLOG_SERVER"
	rekorServer   = "https://api.rekor.dev"
)

// Publish will publish the signature, public key and payload to the tlog
func Publish(signature, payload []byte, publicKey string) error {
	if os.Getenv(tlogEnv) != "1" {
		return nil
	}
	if publicKey == "" {
		return fmt.Errorf("to push to tlog, please pass in path to public key via --public-key")
	}
	pubKey, err := ioutil.ReadFile(publicKey)
	if err != nil {
		return errors.Wrap(err, "reading public key")
	}
	rekorClient, err := app.GetRekorClient(tlogServer())
	if err != nil {
		return err
	}
	re := rekorEntry(payload, signature, pubKey)
	returnVal := models.Rekord{
		APIVersion: swag.String(re.APIVersion()),
		Spec:       re.RekordObj,
	}
	params := entries.NewCreateLogEntryParams()
	params.SetProposedEntry(&returnVal)
	if _, err := rekorClient.Entries.CreateLogEntry(params); err != nil {
		return errors.Wrap(err, "creating log entry")
	}
	fmt.Println("Sucessfully appended to transparency log")
	return nil
}

// Verify will verify the signature, public key and payload are in the tlog, as well as verifying the signature itself
func Verify(signedPayload []cosign.SignedPayload, publicKey string) error {
	if os.Getenv(tlogEnv) != "1" {
		return nil
	}
	pubKey, err := ioutil.ReadFile(publicKey)
	if err != nil {
		return errors.Wrap(err, "reading public key")
	}
	rekorClient, err := app.GetRekorClient(tlogServer())
	if err != nil {
		return err
	}

	for _, sp := range signedPayload {
		params := entries.NewGetLogEntryProofParams()
		searchParams := entries.NewSearchLogQueryParams()
		searchLogQuery := models.SearchLogQuery{}
		// var entry models.ProposedEntry
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

		v := logverifier.New(rfc6962.DefaultHasher)
		if err := v.VerifyInclusionProof(*lep.Payload.LogIndex, *lep.Payload.TreeSize,
			hashes, rootHash, leafHash); err != nil {
			return err
		}
	}
	fmt.Println("Verified signature, payload and public key exist in transparency log")
	return nil
}

func rekorEntry(payload, signature, pubKey []byte) rekord_v001.V001Entry {
	return rekord_v001.V001Entry{
		RekordObj: models.RekordV001Schema{
			Data: &models.RekordV001SchemaData{
				Content: strfmt.Base64(payload),
			},
			Signature: &models.RekordV001SchemaSignature{
				Content: strfmt.Base64(signature),
				Format:  models.RekordV001SchemaSignatureFormatX509,
				PublicKey: &models.RekordV001SchemaSignaturePublicKey{
					Content: strfmt.Base64(pubKey),
				},
			},
		},
	}
}

// tlogServer returns the name of the tlog server, can be overwritten via env var
func tlogServer() string {
	if s := os.Getenv(tlogServerEnv); s != "" {
		return s
	}
	return rekorServer
}
