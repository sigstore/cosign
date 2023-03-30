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
	"errors"

	"github.com/go-openapi/runtime"

	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
)

// EntriesClient is a client that implements entries.ClientService for Rekor
// To use:
// var mClient client.Rekor
// mClient.Entries = &logEntry
type EntriesClient struct {
	Entries []*models.LogEntry
}

func (m *EntriesClient) CreateLogEntry(_ *entries.CreateLogEntryParams, _ ...entries.ClientOption) (*entries.CreateLogEntryCreated, error) {
	if m.Entries != nil {
		return &entries.CreateLogEntryCreated{
			ETag:     "",
			Location: "",
			Payload:  *m.Entries[0],
		}, nil
	}
	return nil, errors.New("entry not provided")
}

func (m *EntriesClient) GetLogEntryByIndex(_ *entries.GetLogEntryByIndexParams, _ ...entries.ClientOption) (*entries.GetLogEntryByIndexOK, error) {
	if m.Entries != nil {
		return &entries.GetLogEntryByIndexOK{
			Payload: *m.Entries[0],
		}, nil
	}
	return nil, errors.New("entry not provided")
}

func (m *EntriesClient) GetLogEntryByUUID(params *entries.GetLogEntryByUUIDParams, opts ...entries.ClientOption) (*entries.GetLogEntryByUUIDOK, error) { //nolint: revive
	if m.Entries != nil {
		return &entries.GetLogEntryByUUIDOK{
			Payload: *m.Entries[0],
		}, nil
	}
	return nil, errors.New("entry not provided")
}

func (m *EntriesClient) SearchLogQuery(params *entries.SearchLogQueryParams, opts ...entries.ClientOption) (*entries.SearchLogQueryOK, error) { //nolint: revive
	resp := []models.LogEntry{}
	if m.Entries != nil {
		for _, entry := range m.Entries {
			resp = append(resp, *entry)
		}
	}
	return &entries.SearchLogQueryOK{
		Payload: resp,
	}, nil
}

// TODO: Implement mock
func (m *EntriesClient) SetTransport(transport runtime.ClientTransport) { //nolint: revive
	// noop
}
