//
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
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/pkg/errors"

	"github.com/sigstore/rekor/cmd/rekor-cli/app"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	rekord_v001 "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
)

const (
	ExperimentalEnv     = "COSIGN_EXPERIMENTAL"
	repoEnv             = "COSIGN_REPOSITORY"
	DockerMediaTypesEnv = "COSIGN_DOCKER_MEDIA_TYPES"
	ServerEnv           = "REKOR_SERVER"
	rekorServer         = "https://api.sigstore.dev"
)

func Experimental() bool {
	if b, err := strconv.ParseBool(os.Getenv(ExperimentalEnv)); err == nil {
		return b
	}
	return false
}

func DockerMediaTypes() bool {
	if b, err := strconv.ParseBool(os.Getenv(DockerMediaTypesEnv)); err == nil {
		return b
	}
	return false
}

func DestinationRef(ref name.Reference, img *remote.Descriptor) (name.Reference, error) {
	dstTag := ref.Context().Tag(Munge(img.Descriptor))
	wantRepo := os.Getenv(repoEnv)
	if wantRepo == "" {
		return dstTag, nil
	}
	// strip registry from image
	oldImage := strings.TrimPrefix(dstTag.Name(), dstTag.RegistryStr())
	newSubrepo := strings.TrimPrefix(wantRepo, dstTag.RegistryStr())

	// replace old subrepo with new one
	subRepo := strings.Split(oldImage, "/")
	if s := strings.SplitAfterN(newSubrepo, "/", 1); len(s) == 1 {
		subRepo[1] = strings.TrimPrefix(s[0], "/")
	} else {
		subRepo[1] = strings.TrimPrefix(s[1], "/")
	}
	subbed := dstTag.RegistryStr() + strings.Join(subRepo, "/")
	return name.ParseReference(subbed)
}

// Upload will upload the signature, public key and payload to the tlog
func UploadTLog(signature, payload []byte, pemBytes []byte) (*models.LogEntryAnon, error) {
	rekorClient, err := app.GetRekorClient(TlogServer())
	if err != nil {
		return nil, err
	}

	re := rekorEntry(payload, signature, pemBytes)
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
		if existsErr, ok := err.(*entries.CreateLogEntryConflict); ok {

			fmt.Println("Signature already exists. Displaying proof")
			uriSplit := strings.Split(existsErr.Location.String(), "/")
			uuid := uriSplit[len(uriSplit)-1]
			return VerifyTLogEntry(rekorClient, uuid)
		}
		return nil, err
	}
	// UUID is at the end of location
	for _, p := range resp.Payload {
		return &p, nil
	}
	return nil, errors.New("bad response from server")
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
