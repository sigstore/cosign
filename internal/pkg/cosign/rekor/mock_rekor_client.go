package rekor

import (
	"github.com/go-openapi/runtime"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
)

// Client that implements entries.ClientService for Rekor
// To use:
// var mClient client.Rekor
// mClient.entries = &MockEntriesClient{}
type MockEntriesClient struct {
}

func (m *MockEntriesClient) CreateLogEntry(params *entries.CreateLogEntryParams, opts ...entries.ClientOption) (*entries.CreateLogEntryCreated, error) {
	return &entries.CreateLogEntryCreated{
		ETag:     "",
		Location: "",
		Payload: map[string]models.LogEntryAnon{
			"sdf": {
				Attestation:    &models.LogEntryAnonAttestation{},
				Body:           nil,
				IntegratedTime: new(int64),
				LogID:          new(string),
				LogIndex:       new(int64),
				Verification:   &models.LogEntryAnonVerification{},
			},
		},
	}, nil
}

// TODO: Implement mock
func (m *MockEntriesClient) GetLogEntryByIndex(params *entries.GetLogEntryByIndexParams, opts ...entries.ClientOption) (*entries.GetLogEntryByIndexOK, error) {
	return nil, nil
}

// TODO: Implement mock
func (m *MockEntriesClient) GetLogEntryByUUID(params *entries.GetLogEntryByUUIDParams, opts ...entries.ClientOption) (*entries.GetLogEntryByUUIDOK, error) {
	return nil, nil
}

// TODO: Implement mock
func (m *MockEntriesClient) SearchLogQuery(params *entries.SearchLogQueryParams, opts ...entries.ClientOption) (*entries.SearchLogQueryOK, error) {
	return nil, nil
}

// TODO: Implement mock
func (m *MockEntriesClient) SetTransport(transport runtime.ClientTransport) {
}
