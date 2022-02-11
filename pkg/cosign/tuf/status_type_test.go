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

package tuf

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestMarshalStatusType(t *testing.T) {
	statuses := []StatusKind{UnknownStatus, Active, Expired}
	bytes, err := json.Marshal(statuses)
	if err != nil {
		t.Fatalf("expected no error marshalling struct, got: %v", err)
	}
	expected := `["Unknown","Active","Expired"]`
	if string(bytes) != expected {
		t.Fatalf("error while marshalling, expected: %s, got: %s", expected, bytes)
	}
}

func TestMarshalInvalidStatusType(t *testing.T) {
	invalidStatus := 42
	statuses := []StatusKind{StatusKind(invalidStatus)}
	bytes, err := json.Marshal(statuses)
	if bytes != nil {
		t.Fatalf("expected error marshalling struct, got: %v", bytes)
	}
	expectedErr := fmt.Sprintf("error while marshalling, int(StatusKind)=%d not valid", invalidStatus)
	if !strings.Contains(err.Error(), expectedErr) {
		t.Fatalf("expected error marshalling struct, expected: %v, got: %v", expectedErr, err)
	}
}

func TestUnmarshalStatusType(t *testing.T) {
	var statuses []StatusKind
	j := json.RawMessage(`["expired", "active", "unknown"]`)
	err := json.Unmarshal(j, &statuses)
	if err != nil {
		t.Fatalf("expected no error unmarshalling struct, got: %v", err)
	}
	if !reflect.DeepEqual(statuses, []StatusKind{Expired, Active, UnknownStatus}) {
		t.Fatalf("expected [Expired, Active, Unknown], got: %v", statuses)
	}
}

func TestUnmarshalStatusTypeCapitalization(t *testing.T) {
	// Any capitalization is allowed.
	var statuses []StatusKind
	j := json.RawMessage(`["eXpIrEd", "aCtIvE", "uNkNoWn"]`)
	err := json.Unmarshal(j, &statuses)
	if err != nil {
		t.Fatalf("expected no error unmarshalling struct, got: %v", err)
	}
	if !reflect.DeepEqual(statuses, []StatusKind{Expired, Active, UnknownStatus}) {
		t.Fatalf("expected [Expired, Active, Unknown], got: %v", statuses)
	}
}

func TestUnmarshalInvalidStatusType(t *testing.T) {
	var statuses []StatusKind
	invalidStatus := "invalid"
	j := json.RawMessage(fmt.Sprintf(`["%s"]`, invalidStatus))
	err := json.Unmarshal(j, &statuses)
	expectedErr := fmt.Sprintf("error while unmarshalling, StatusKind=%s not valid", invalidStatus)
	if !strings.Contains(err.Error(), expectedErr) {
		t.Fatalf("expected error unmarshalling struct, expected: %v, got: %v", expectedErr, err)
	}
}
