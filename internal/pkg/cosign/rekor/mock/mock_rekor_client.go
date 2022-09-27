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
	Entries *models.LogEntry
}

func (m *EntriesClient) CreateLogEntry(params *entries.CreateLogEntryParams, opts ...entries.ClientOption) (*entries.CreateLogEntryCreated, error) {
	if m.Entries != nil {
		return &entries.CreateLogEntryCreated{
			ETag:     "",
			Location: "",
			Payload:  *m.Entries,
		}, nil
	}
	return nil, errors.New("entry not provided")
}

func (m *EntriesClient) GetLogEntryByIndex(params *entries.GetLogEntryByIndexParams, opts ...entries.ClientOption) (*entries.GetLogEntryByIndexOK, error) {
	if m.Entries != nil {
		return &entries.GetLogEntryByIndexOK{
			Payload: *m.Entries,
		}, nil
	}
	return nil, errors.New("entry not provided")
}

func (m *EntriesClient) GetLogEntryByUUID(params *entries.GetLogEntryByUUIDParams, opts ...entries.ClientOption) (*entries.GetLogEntryByUUIDOK, error) {
	if m.Entries != nil {
		return &entries.GetLogEntryByUUIDOK{
			Payload: *m.Entries,
		}, nil
	}
	return nil, errors.New("entry not provided")
}

func (m *EntriesClient) SearchLogQuery(params *entries.SearchLogQueryParams, opts ...entries.ClientOption) (*entries.SearchLogQueryOK, error) {
	resp := []models.LogEntry{}
	if m.Entries != nil {
		resp = append(resp, *m.Entries)
	}
	return &entries.SearchLogQueryOK{
		Payload: resp,
	}, nil
}

// TODO: Implement mock
func (m *EntriesClient) SetTransport(transport runtime.ClientTransport) {
}
