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

package rego

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/open-policy-agent/opa/rego"
	"github.com/pkg/errors"
)

func ValidateJSON(jsonBody []byte, entrypoints []string) error {
	ctx := context.Background()

	r := rego.New(
		rego.Query("data.signature.allow"), // hardcoded, ? data.cosign.allow→
		rego.Load(entrypoints, nil))

	query, err := r.PrepareForEval(ctx)
	if err != nil {
		return err
	}

	var input interface{}
	dec := json.NewDecoder(bytes.NewBuffer(jsonBody))
	dec.UseNumber()
	if err := dec.Decode(&input); err != nil {
		return err
	}

	rs, err := query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return err
	}

	if rs.Allowed() {
		return nil
	}
	return errors.New("rego validation failed")
}
