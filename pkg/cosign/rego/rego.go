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
	"fmt"

	"github.com/open-policy-agent/opa/rego"
)

func ValidateJSON(jsonBody []byte, entrypoints []string) []error {
	ctx := context.Background()

	r := rego.New(
		rego.Query("data.signature.deny"), // hardcoded, ? data.cosign.allow→
		rego.Load(entrypoints, nil))

	query, err := r.PrepareForEval(ctx)
	if err != nil {
		return []error{err}
	}

	var input interface{}
	dec := json.NewDecoder(bytes.NewBuffer(jsonBody))
	dec.UseNumber()
	if err := dec.Decode(&input); err != nil {
		return []error{err}
	}

	rs, err := query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return []error{err}
	}

	if rs.Allowed() {
		return nil
	}

	var errs []error
	for _, result := range rs {
		for _, expression := range result.Expressions {
			for _, v := range expression.Value.([]interface{}) {
				if s, ok := v.(string); ok {
					errs = append(errs, fmt.Errorf(s))
				} else {
					errs = append(errs, fmt.Errorf("%s", v))
				}
			}
		}
	}
	return errs
}
