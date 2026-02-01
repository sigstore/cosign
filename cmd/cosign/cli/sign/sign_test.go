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

package sign

import (
	"encoding/json"
	"errors"
	"testing"

	intotov1 "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/pkg/types"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

// TestSignCmdLocalKeyAndSk verifies the SignCmd returns an error
// if both a local key path and a sk are specified
func TestSignCmdLocalKeyAndSk(t *testing.T) {
	ro := &options.RootOptions{Timeout: options.DefaultTimeout}

	for _, ko := range []options.KeyOpts{
		// local and sk keys
		{
			KeyRef:   "testLocalPath",
			PassFunc: generate.GetPass,
			Sk:       true,
		},
	} {
		so := options.SignOptions{}
		err := SignCmd(t.Context(), ro, ko, so, nil)
		if (errors.Is(err, &options.KeyParseError{}) == false) {
			t.Fatal("expected KeyParseError")
		}
	}
}

func TestInTotoStatementHasPredicate(t *testing.T) {
	annoStruct, _ := structpb.NewStruct(map[string]any{})
	subject := intotov1.ResourceDescriptor{
		Digest:      map[string]string{"sha256": "deadbeef"},
		Annotations: annoStruct,
	}

	statement := &intotov1.Statement{
		Type:          intotov1.StatementTypeUri,
		Subject:       []*intotov1.ResourceDescriptor{&subject},
		PredicateType: types.CosignSignPredicateType,
		Predicate:     &structpb.Struct{},
	}

	payload, err := protojson.Marshal(statement)
	if err != nil {
		t.Fatalf("failed to marshal statement: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}

	if _, ok := result["predicate"]; !ok {
		t.Error("in-toto statement must contain a 'predicate' field to comply with the in-toto specification")
	}

	if _, ok := result["_type"]; !ok {
		t.Error("in-toto statement must contain a '_type' field")
	}
	if _, ok := result["subject"]; !ok {
		t.Error("in-toto statement must contain a 'subject' field")
	}
	if _, ok := result["predicateType"]; !ok {
		t.Error("in-toto statement must contain a 'predicateType' field")
	}
}
