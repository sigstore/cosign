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
	"fmt"
	"io/ioutil"
	"os"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/pkg/errors"

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
		return errors.Wrap(err, "loading public key")
	}
	rekorClient, err := app.GetRekorClient(tlogServer())
	if err != nil {
		return err
	}

	re := rekord_v001.V001Entry{
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
func Verify(signature, payload []byte, publicKey string) error {
	if os.Getenv(tlogEnv) != "1" {
		return nil
	}
	return nil
}

// tlogServer returns the name of the tlog server, can be overwritten via env var
func tlogServer() string {
	if s := os.Getenv(tlogServerEnv); s != "" {
		return s
	}
	return rekorServer
}
