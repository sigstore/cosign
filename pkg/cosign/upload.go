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

package cosign

import (
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/pkg/errors"

	"github.com/sigstore/rekor/cmd/cli/app"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	rekord_v001 "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
)

const (
	ExperimentalEnv = "COSIGN_EXPERIMENTAL"
	ServerEnv       = "REKOR_SERVER"
	rekorServer     = "https://api.rekor.dev"
)

func Experimental() bool {
	return os.Getenv(ExperimentalEnv) == "1"
}

// Upload will upload the signature, public key and payload to the tlog
func UploadTLog(signature, payload []byte, publicKey *ecdsa.PublicKey) (string, error) {
	rekorClient, err := app.GetRekorClient(TlogServer())
	if err != nil {
		return "", err
	}
	wrappedKey, err := MarshalPublicKey(publicKey)
	if err != nil {
		return "", err
	}

	re := rekorEntry(payload, signature, wrappedKey)
	returnVal := models.Rekord{
		APIVersion: swag.String(re.APIVersion()),
		Spec:       re.RekordObj,
	}
	params := entries.NewCreateLogEntryParams()
	params.SetProposedEntry(&returnVal)
	resp, err := rekorClient.Entries.CreateLogEntry(params)
	if err != nil {
		// If the entry already exists, we get a specific error.
		// Here, we display the proof and succeed.
		if _, ok := err.(*entries.CreateLogEntryConflict); ok {
			cs := SignedPayload{
				Base64Signature: base64.StdEncoding.EncodeToString(signature),
				Payload:         payload,
			}
			fmt.Println("Signature already exists. Displaying proof")

			return FindTlogEntry(rekorClient, cs.Base64Signature, cs.Payload, wrappedKey)

		}
		return "", err
	}
	// UUID is at the end of location
	for _, p := range resp.Payload {
		return strconv.FormatInt(*p.LogIndex, 10), nil
	}
	return "", errors.New("bad response from server")
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
func TlogServer() string {
	if s := os.Getenv(ServerEnv); s != "" {
		return s
	}
	return rekorServer
}
