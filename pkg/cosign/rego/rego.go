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
	"reflect"

	"github.com/open-policy-agent/opa/rego"
)

// The query below should meet the following requirements:
// * Provides no Bindings. Do not use a query that sets a variable, e.g. x := data.signature.allow
// * Queries for a single value.
const QUERY = "data.signature.allow"

// CosignRegoPackageName defines the expected package name of a provided rego module
const CosignRegoPackageName = "sigstore"

// CosignEvaluationRule defines the expected evaluation role of a provided rego module
const CosignEvaluationRule = "isCompliant"

// CosignRuleResult defines a expected result object when wrapping the custom messages of the result of our cosign rego rule
type CosignRuleResult struct {
	Warnings string `json:"warnings,omitempty"`
	Errors   string `json:"errors,omitempty"`
	Result   bool   `json:"result,omitempty"`
}

func ValidateJSON(jsonBody []byte, entrypoints []string) []error {
	ctx := context.Background()

	r := rego.New(
		rego.Query(QUERY),
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

	// Ensure the resultset contains a single result where the Expression contains a single value
	// which is true and there are no Bindings.
	if rs.Allowed() {
		return nil
	}

	var errs []error
	for _, result := range rs {
		for _, expression := range result.Expressions {
			errs = append(errs, fmt.Errorf("expression value, %v, is not true", expression))
		}
	}

	// When rs.Allowed() is not true and len(rs) is 0, the result is undefined. This is a policy
	// check failure.
	if len(errs) == 0 {
		errs = append(errs, fmt.Errorf("result is undefined for query '%s'", QUERY))
	}
	return errs
}

// ValidateJSONWithModuleInput takes the body of the results to evaluate and the defined module
// in a policy to validate against the input data
func ValidateJSONWithModuleInput(jsonBody []byte, moduleInput string) (warnings error, errors error) {
	ctx := context.Background()
	query := fmt.Sprintf("%s = data.%s.%s", CosignEvaluationRule, CosignRegoPackageName, CosignEvaluationRule)
	module := fmt.Sprintf("%s.rego", CosignRegoPackageName)

	r := rego.New(
		rego.Query(query),
		rego.Module(module, moduleInput))

	evalQuery, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, err
	}

	var input interface{}
	dec := json.NewDecoder(bytes.NewBuffer(jsonBody))
	dec.UseNumber()
	if err := dec.Decode(&input); err != nil {
		return nil, err
	}

	rs, err := evalQuery.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, err
	}

	var response []interface{}
	var isComplaint bool
	for _, result := range rs {
		switch reflect.TypeOf(result.Bindings[CosignEvaluationRule]) {
		case reflect.TypeOf(response):
			return evaluateRegoEvalMapResult(query, result.Bindings[CosignEvaluationRule].([]interface{}))
		case reflect.TypeOf(isComplaint):
			fmt.Printf("isComplaint %v\n", isComplaint)
			isComplaint, ok := result.Bindings[CosignEvaluationRule].(bool)
			if ok && isComplaint {
				return nil, nil
			}
		}
	}

	return nil, fmt.Errorf("policy is not compliant for query '%s'", query)
}

func evaluateRegoEvalMapResult(query string, response []interface{}) (warnings error, errors error) {
	var warnMsg error
	errMsg := fmt.Errorf("policy is not compliant for query '%s'", query)
	for _, r := range response {
		rMap := r.(map[string]interface{})
		mapBytes, err := json.Marshal(rMap)
		if err != nil {
			return nil, fmt.Errorf("policy is not compliant for query '%s' due to parsing errors: %w", query, err)
		}
		var resultObject CosignRuleResult
		err = json.Unmarshal(mapBytes, &resultObject)
		if err != nil {
			return nil, fmt.Errorf("policy is not compliant for query '%s' due to parsing errors: %w", query, err)
		}
		fmt.Printf("resultObject %v\n", resultObject)

		// Check if it is complaint
		if resultObject.Result {
			return fmt.Errorf(resultObject.Warnings), nil
		}
		warnMsg = fmt.Errorf(resultObject.Warnings)
		errMsg = fmt.Errorf("policy is not compliant for query '%s' with errors: %s", query, resultObject.Errors)
	}
	return warnMsg, errMsg
}
