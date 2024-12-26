//
// Copyright 2024 The Sigstore Authors.
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
	"runtime"
	"testing"
)

var policyTypes = []string{"cue", "rego"}

func catchPanics() {
	if r := recover(); r != nil {
		var errStr string
		switch err := r.(type) {
		case string:
			errStr = err
		case runtime.Error:
			errStr = err.Error()
		case error:
			errStr = err.Error()
		}
		switch {
		case errStr == "freeNode: nodeContext out of sync":
			return
		case errStr == "unreachable":
			return
		default:
			panic(errStr)
		}
	}
}

func FuzzEvaluatePolicyAgainstJSON(f *testing.F) {
	f.Fuzz(func(_ *testing.T, name, policyBody string, jsonBytes []byte, policyType uint8) {
		defer catchPanics()
		choosePolicyType := policyTypes[int(policyType)%len(policyTypes)]
		EvaluatePolicyAgainstJSON(context.Background(), name, choosePolicyType, policyBody, jsonBytes)
	})
}
