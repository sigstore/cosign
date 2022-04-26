//
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

package policy

import (
	"context"
	"fmt"

	"cuelang.org/go/cue/cuecontext"

	"knative.dev/pkg/logging"
)

// EvaluatePolicyAgainstJson is used to run a policy engine against JSON bytes.
// These bytes can be for example Attestations, or ClusterImagePolicy result
// types.
// name - which attestation are we evaluating
// policyType - cue|rego
// policyBody - String representing either cue or rego language
// jsonBytes - Bytes to evaluate against the policyBody in the given language
func EvaluatePolicyAgainstJSON(ctx context.Context, name, policyType string, policyBody string, jsonBytes []byte) error {
	logging.FromContext(ctx).Debugf("Evaluating JSON: %s against policy: %s", string(jsonBytes), policyBody)
	switch policyType {
	case "cue":
		cueValidationErr := evaluateCue(ctx, jsonBytes, policyBody)
		if cueValidationErr != nil {
			return fmt.Errorf("failed evaluating cue policy for %s : %s", name, cueValidationErr.Error()) // nolint
		}
	case "rego":
		regoValidationErr := evaluateRego(ctx, jsonBytes, policyBody)
		if regoValidationErr != nil {
			return fmt.Errorf("failed evaluating rego policy for type %s", name)
		}
	default:
		return fmt.Errorf("sorry Type %s is not supported yet", policyType)
	}
	return nil
}

// evaluateCue evaluates a cue policy `evaluator` against `attestation`
func evaluateCue(ctx context.Context, attestation []byte, evaluator string) error {
	logging.FromContext(ctx).Infof("Evaluating attestation: %s", string(attestation))
	logging.FromContext(ctx).Infof("Evaluator: %s", evaluator)

	cueCtx := cuecontext.New()
	cueEvaluator := cueCtx.CompileString(evaluator)
	if cueEvaluator.Err() != nil {
		return fmt.Errorf("failed to compile the cue policy with error: %w", cueEvaluator.Err())
	}
	cueAtt := cueCtx.CompileBytes(attestation)
	if cueAtt.Err() != nil {
		return fmt.Errorf("failed to compile the attestation data with error: %w", cueAtt.Err())
	}
	result := cueEvaluator.Unify(cueAtt)
	if err := result.Validate(); err != nil {
		return fmt.Errorf("failed to evaluate the policy with error: %w", err)
	}
	return nil
}

// evaluateRego evaluates a rego policy `evaluator` against `attestation`
func evaluateRego(ctx context.Context, attestation []byte, evaluator string) error {
	// TODO(vaikas) Fix this
	// The existing stuff wants files, and it doesn't work. There must be
	// a way to load it from a []byte like we can do with cue. Tomorrows problem
	// regoValidationErrs := rego.ValidateJSON(payload, regoPolicies)
	return fmt.Errorf("TODO(vaikas): Don't know how to this from bytes yet")
}
