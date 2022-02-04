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

func TestMarshalUsageType(t *testing.T) {
	usages := []UsageKind{UnknownUsage, Fulcio, Rekor, CTFE}
	bytes, err := json.Marshal(usages)
	if err != nil {
		t.Fatalf("expected no error marshalling struct, got: %v", err)
	}
	expected := `["Unknown","Fulcio","Rekor","CTFE"]`
	if string(bytes) != expected {
		t.Fatalf("error while marshalling, expected: %s, got: %s", expected, bytes)
	}
}

func TestMarshalInvalidUsageType(t *testing.T) {
	invalidUsage := 42
	usages := []UsageKind{UsageKind(invalidUsage)}
	bytes, err := json.Marshal(usages)
	if bytes != nil {
		t.Fatalf("expected error marshalling struct, got: %v", bytes)
	}
	expectedErr := fmt.Sprintf("error while marshalling, int(UsageKind)=%d not valid", invalidUsage)
	if !strings.Contains(err.Error(), expectedErr) {
		t.Fatalf("expected error marshalling struct, expected: %v, got: %v", expectedErr, err)
	}
}

func TestUnmarshalUsageType(t *testing.T) {
	var usages []UsageKind
	j := json.RawMessage(`["fulcio", "rekor", "ctfe", "unknown"]`)
	err := json.Unmarshal(j, &usages)
	if err != nil {
		t.Fatalf("expected no error unmarshalling struct, got: %v", err)
	}
	if !reflect.DeepEqual(usages, []UsageKind{Fulcio, Rekor, CTFE, UnknownUsage}) {
		t.Fatalf("expected [Fulcio, Rekor, CTFE, UnknownUsage], got: %v", usages)
	}
}

func TestUnmarshalUsageTypeCapitalization(t *testing.T) {
	// Any capitalization is allowed.
	var usages []UsageKind
	j := json.RawMessage(`["fUlCiO", "rEkOr", "cTfE", "uNkNoWn"]`)
	err := json.Unmarshal(j, &usages)
	if err != nil {
		t.Fatalf("expected no error unmarshalling struct, got: %v", err)
	}
	if !reflect.DeepEqual(usages, []UsageKind{Fulcio, Rekor, CTFE, UnknownUsage}) {
		t.Fatalf("expected [Fulcio, Rekor, CTFE, UnknownUsage], got: %v", usages)
	}
}

func TestUnmarshalInvalidUsageType(t *testing.T) {
	var usages []UsageKind
	invalidUsage := "invalid"
	j := json.RawMessage(fmt.Sprintf(`["%s"]`, invalidUsage))
	err := json.Unmarshal(j, &usages)
	expectedErr := fmt.Sprintf("error while unmarshalling, UsageKind=%s not valid", invalidUsage)
	if !strings.Contains(err.Error(), expectedErr) {
		t.Fatalf("expected error unmarshalling struct, expected: %v, got: %v", expectedErr, err)
	}
}
