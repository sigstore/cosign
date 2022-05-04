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

package mock

import (
	"encoding/base64"
	"encoding/hex"

	"github.com/go-openapi/runtime"
	"github.com/google/trillian/merkle/rfc6962"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
)

var (
	lea = models.LogEntryAnon{
		Attestation:    &models.LogEntryAnonAttestation{},
		Body:           base64.StdEncoding.EncodeToString([]byte("asdf")),
		IntegratedTime: new(int64),
		LogID:          new(string),
		LogIndex:       new(int64),
		Verification: &models.LogEntryAnonVerification{
			InclusionProof: &models.InclusionProof{
				RootHash: new(string),
				TreeSize: new(int64),
				LogIndex: new(int64),
			},
		},
	}
	data = models.LogEntry{
		uuid(lea): lea,
	}
)

// uuid generates the UUID for the given LogEntry.
// This is effectively a reimplementation of
// pkg/cosign/tlog.go -> verifyUUID / ComputeLeafHash, but separated
// to avoid a circular dependency.
// TODO?: Perhaps we should refactor the tlog libraries into a separate
// package?
func uuid(e models.LogEntryAnon) string {
	entryBytes, err := base64.StdEncoding.DecodeString(e.Body.(string))
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(rfc6962.DefaultHasher.HashLeaf(entryBytes))
}

// EntriesClient is a client that implements entries.ClientService for Rekor
// To use:
// var mClient client.Rekor
// mClient.entries = &EntriesClient{}
type EntriesClient struct {
	Entries models.LogEntry
}

func (m *EntriesClient) CreateLogEntry(params *entries.CreateLogEntryParams, opts ...entries.ClientOption) (*entries.CreateLogEntryCreated, error) {
	return &entries.CreateLogEntryCreated{
		ETag:     "",
		Location: "",
		Payload:  data,
	}, nil
}

func (m *EntriesClient) GetLogEntryByIndex(params *entries.GetLogEntryByIndexParams, opts ...entries.ClientOption) (*entries.GetLogEntryByIndexOK, error) {
	return &entries.GetLogEntryByIndexOK{
		Payload: data,
	}, nil
}

func (m *EntriesClient) GetLogEntryByUUID(params *entries.GetLogEntryByUUIDParams, opts ...entries.ClientOption) (*entries.GetLogEntryByUUIDOK, error) {
	return &entries.GetLogEntryByUUIDOK{
		Payload: data,
	}, nil
}

func (m *EntriesClient) SearchLogQuery(params *entries.SearchLogQueryParams, opts ...entries.ClientOption) (*entries.SearchLogQueryOK, error) {
	return &entries.SearchLogQueryOK{
		Payload: []models.LogEntry{data},
	}, nil
}

// TODO: Implement mock
func (m *EntriesClient) SetTransport(transport runtime.ClientTransport) {
}
