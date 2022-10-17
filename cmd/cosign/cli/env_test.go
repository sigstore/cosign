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

package cli

import (
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/sigstore/cosign/pkg/cosign/env"
)

const (
	VariableTest1 env.Variable = "COSIGN_TEST1"
	VariableTest2 env.Variable = "COSIGN_TEST2"
	VariableTest3 env.Variable = "COSIGN_TEST3"

	expectedWithoutDescription = `COSIGN_TEST1="abcd"
COSIGN_TEST2=""
`
	expectedWithDescription = `# COSIGN_TEST1 is the first test variable
# Expects: test1 value
COSIGN_TEST1="abcd"
# COSIGN_TEST2 is the second test variable
# Expects: test2 value
COSIGN_TEST2=""
`

	expectedWithHiddenSensitive = `# COSIGN_TEST1 is the first test variable
# Expects: test1 value
COSIGN_TEST1="abcd"
# COSIGN_TEST2 is the second test variable
# Expects: test2 value
COSIGN_TEST2="******"
`

	expectedWithSensitive = `# COSIGN_TEST1 is the first test variable
# Expects: test1 value
COSIGN_TEST1="abcd"
# COSIGN_TEST2 is the second test variable
# Expects: test2 value
COSIGN_TEST2="1234"
`

	expectedSensitiveWithoutDescription = `COSIGN_TEST1="abcd"
COSIGN_TEST2="1234"
`

	expectedWithNonRegisteredEnv = `# COSIGN_TEST1 is the first test variable
# Expects: test1 value
COSIGN_TEST1="abcd"
# COSIGN_TEST2 is the second test variable
# Expects: test2 value
COSIGN_TEST2=""
# Environment variables below are not registered with cosign,
# but might still influence cosign's behavior.
COSIGN_TEST3=abcd
`

	expectedWithNonRegisteredEnvNoDesc = `COSIGN_TEST1="abcd"
COSIGN_TEST2=""
COSIGN_TEST3=abcd
`
)

var (
	testingEnvVars = map[string]string{}
)

func tGetEnv() envGetter {
	return func(key env.Variable) string {
		return testingEnvVars[key.String()]
	}
}
func tGetEnviron() environGetter {
	return func() []string {
		var s []string

		for k, v := range testingEnvVars {
			s = append(s, fmt.Sprintf("%s=%s", k, v))
		}

		return s
	}
}

func TestPrintEnv(t *testing.T) {
	variables := map[env.Variable]env.VariableOpts{
		VariableTest1: {
			Description: "is the first test variable",
			Expects:     "test1 value",
			Sensitive:   false,
		},
		VariableTest2: {
			Description: "is the second test variable",
			Expects:     "test2 value",
			Sensitive:   true,
		},
	}

	tests := []struct {
		name                 string
		environmentVariables map[string]string
		registeredVariables  map[env.Variable]env.VariableOpts
		showDescriptions     bool
		showSensitiveValues  bool
		expectedOutput       string
	}{
		{
			name: "no descriptions and sensitive variables",
			environmentVariables: map[string]string{
				"COSIGN_TEST1": "abcd",
				"COSIGN_TEST2": "",
			},
			registeredVariables: variables,
			showDescriptions:    false,
			showSensitiveValues: false,
			expectedOutput:      expectedWithoutDescription,
		},
		{
			name: "descriptions but sensitive variable is unset",
			environmentVariables: map[string]string{
				"COSIGN_TEST1": "abcd",
				"COSIGN_TEST2": "",
			},
			registeredVariables: variables,
			showDescriptions:    true,
			showSensitiveValues: false,
			expectedOutput:      expectedWithDescription,
		},
		{
			name: "sensitive variable is non-empty but show sensitive variables is disabled",
			environmentVariables: map[string]string{
				"COSIGN_TEST1": "abcd",
				"COSIGN_TEST2": "1234",
			},
			registeredVariables: variables,
			showDescriptions:    true,
			showSensitiveValues: false,
			expectedOutput:      expectedWithHiddenSensitive,
		},
		{
			name: "sensitive variable is empty",
			environmentVariables: map[string]string{
				"COSIGN_TEST1": "abcd",
				"COSIGN_TEST2": "",
			},
			registeredVariables: variables,
			showDescriptions:    true,
			showSensitiveValues: true,
			expectedOutput:      expectedWithDescription,
		},
		{
			name: "sensitive variable is non-empty and show sensitive variables is enabled",
			environmentVariables: map[string]string{
				"COSIGN_TEST1": "abcd",
				"COSIGN_TEST2": "1234",
			},
			registeredVariables: variables,
			showDescriptions:    true,
			showSensitiveValues: true,
			expectedOutput:      expectedWithSensitive,
		},
		{
			name: "sensitive variable is non-empty but show descriptions is disabled",
			environmentVariables: map[string]string{
				"COSIGN_TEST1": "abcd",
				"COSIGN_TEST2": "1234",
			},
			registeredVariables: variables,
			showDescriptions:    false,
			showSensitiveValues: true,
			expectedOutput:      expectedSensitiveWithoutDescription,
		},
		{
			name: "print unregistered variable with description",
			environmentVariables: map[string]string{
				"COSIGN_TEST1": "abcd",
				"COSIGN_TEST2": "",
				"COSIGN_TEST3": "abcd",
			},
			registeredVariables: variables,
			showDescriptions:    true,
			showSensitiveValues: false,
			expectedOutput:      expectedWithNonRegisteredEnv,
		},
		{
			name: "print unregistered variable without description",
			environmentVariables: map[string]string{
				"COSIGN_TEST1": "abcd",
				"COSIGN_TEST2": "",
				"COSIGN_TEST3": "abcd",
			},
			registeredVariables: variables,
			showDescriptions:    false,
			showSensitiveValues: false,
			expectedOutput:      expectedWithNonRegisteredEnvNoDesc,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set needed environment variables
			testingEnvVars = tt.environmentVariables
			for k, v := range testingEnvVars {
				t.Log(k)
				t.Log(v)
			}

			orgStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			printEnv(tt.registeredVariables, tGetEnv(), tGetEnviron(), tt.showDescriptions, tt.showSensitiveValues)

			w.Close()
			out, _ := io.ReadAll(r)
			os.Stdout = orgStdout

			if tt.expectedOutput != string(out) {
				t.Errorf("Expected to get %q\n, but got %q", tt.expectedOutput, string(out))
			}
		})
	}
}
