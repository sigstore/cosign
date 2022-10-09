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

package env

import (
	"io"
	"os"
	"testing"
)

func TestGetenv(t *testing.T) {
	os.Setenv(VariableExperimental.String(), "1")
	if val := Getenv(VariableExperimental); val != "1" {
		t.Errorf("expected to get \"1\", but got %q", val)
	}
}

func TestGetenvUnset(t *testing.T) {
	os.Unsetenv(VariableExperimental.String())
	if val := Getenv(VariableExperimental); val != "" {
		t.Errorf("expected to get \"\", but got %q", val)
	}
}

func TestLookupEnv(t *testing.T) {
	os.Setenv(VariableExperimental.String(), "1")
	val, f := LookupEnv(VariableExperimental)
	if !f {
		t.Errorf("expected to find %q, but it's not set", VariableExperimental.String())
	}
	if val != "1" {
		t.Errorf("expected to get value \"1\", but got %q", val)
	}
}

func TestLookupEnvEmpty(t *testing.T) {
	os.Setenv(VariableExperimental.String(), "")
	val, f := LookupEnv(VariableExperimental)
	if !f {
		t.Errorf("expected to find %q, but it's not set", VariableExperimental.String())
	}
	if val != "" {
		t.Errorf("expected to get value \"\", but got %q", val)
	}
}

func TestLookupEnvUnset(t *testing.T) {
	os.Unsetenv(VariableExperimental.String())
	val, f := LookupEnv(VariableExperimental)
	if f {
		t.Errorf("expected to not find %q, but it's set to %q", VariableExperimental.String(), val)
	}
}

const (
	VariableTest1 Variable = "COSIGN_TEST1"
	VariableTest2 Variable = "COSIGN_TEST2"

	expectedPrintWithoutDescription = `COSIGN_TEST1="abcd"
COSIGN_TEST2=""
`
	expectedPrintWithDescription = `# COSIGN_TEST1 is the first test variable
COSIGN_TEST1="abcd"
# COSIGN_TEST2 is the second test variable
COSIGN_TEST2=""
`

	expectedPrintWithHiddenSensitive = `# COSIGN_TEST1 is the first test variable
COSIGN_TEST1="abcd"
# COSIGN_TEST2 is the second test variable
COSIGN_TEST2="******"
`

	expectedPrintWithSensitive = `# COSIGN_TEST1 is the first test variable
COSIGN_TEST1="abcd"
# COSIGN_TEST2 is the second test variable
COSIGN_TEST2="1234"
`

	expectedPrintSensitiveWithoutDescription = `COSIGN_TEST1="abcd"
COSIGN_TEST2="1234"
`
)

func TestPrintEnv(t *testing.T) {
	tests := []struct {
		name                 string
		prepareFn            func()
		environmentVariables map[Variable]VariableOpts
		showDescriptions     bool
		showSensitiveValues  bool
		expectedOutput       string
	}{
		{
			name: "no descriptions and sensitive variables",
			prepareFn: func() {
				os.Setenv("COSIGN_TEST1", "abcd")
				os.Setenv("COSIGN_TEST2", "")
			},
			environmentVariables: map[Variable]VariableOpts{
				VariableTest1: {
					Description: "is the first test variable",
					Sensitive:   false,
				},
				VariableTest2: {
					Description: "is the second test variable",
					Sensitive:   true,
				},
			},
			showDescriptions:    false,
			showSensitiveValues: false,
			expectedOutput:      expectedPrintWithoutDescription,
		},
		{
			name: "descriptions but sensitive variable is unset",
			prepareFn: func() {
				os.Setenv("COSIGN_TEST1", "abcd")
				os.Setenv("COSIGN_TEST2", "")
			},
			environmentVariables: map[Variable]VariableOpts{
				VariableTest1: {
					Description: "is the first test variable",
					Sensitive:   false,
				},
				VariableTest2: {
					Description: "is the second test variable",
					Sensitive:   true,
				},
			},
			showDescriptions:    true,
			showSensitiveValues: false,
			expectedOutput:      expectedPrintWithDescription,
		},
		{
			name: "sensitive variable is non-empty but show sensitive variables is disabled",
			prepareFn: func() {
				os.Setenv("COSIGN_TEST1", "abcd")
				os.Setenv("COSIGN_TEST2", "1234")
			},
			environmentVariables: map[Variable]VariableOpts{
				VariableTest1: {
					Description: "is the first test variable",
					Sensitive:   false,
				},
				VariableTest2: {
					Description: "is the second test variable",
					Sensitive:   true,
				},
			},
			showDescriptions:    true,
			showSensitiveValues: false,
			expectedOutput:      expectedPrintWithHiddenSensitive,
		},
		{
			name: "sensitive variable is empty",
			prepareFn: func() {
				os.Setenv("COSIGN_TEST1", "abcd")
				os.Setenv("COSIGN_TEST2", "")
			},
			environmentVariables: map[Variable]VariableOpts{
				VariableTest1: {
					Description: "is the first test variable",
					Sensitive:   false,
				},
				VariableTest2: {
					Description: "is the second test variable",
					Sensitive:   true,
				},
			},
			showDescriptions:    true,
			showSensitiveValues: true,
			expectedOutput:      expectedPrintWithDescription,
		},
		{
			name: "sensitive variable is non-empty and show sensitive variables is enabled",
			prepareFn: func() {
				os.Setenv("COSIGN_TEST1", "abcd")
				os.Setenv("COSIGN_TEST2", "1234")
			},
			environmentVariables: map[Variable]VariableOpts{
				VariableTest1: {
					Description: "is the first test variable",
					Sensitive:   false,
				},
				VariableTest2: {
					Description: "is the second test variable",
					Sensitive:   true,
				},
			},
			showDescriptions:    true,
			showSensitiveValues: true,
			expectedOutput:      expectedPrintWithSensitive,
		},
		{
			name: "sensitive variable is non-empty but show descriptions is disabled",
			prepareFn: func() {
				os.Setenv("COSIGN_TEST1", "abcd")
				os.Setenv("COSIGN_TEST2", "1234")
			},
			environmentVariables: map[Variable]VariableOpts{
				VariableTest1: {
					Description: "is the first test variable",
					Sensitive:   false,
				},
				VariableTest2: {
					Description: "is the second test variable",
					Sensitive:   true,
				},
			},
			showDescriptions:    false,
			showSensitiveValues: true,
			expectedOutput:      expectedPrintSensitiveWithoutDescription,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.prepareFn()
			environmentVariables = tt.environmentVariables

			orgStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			PrintEnv(tt.showDescriptions, tt.showSensitiveValues)

			w.Close()
			out, _ := io.ReadAll(r)
			os.Stdout = orgStdout

			if tt.expectedOutput != string(out) {
				t.Errorf("Expected to get %q\n, but got %q", tt.expectedOutput, string(out))
			}
		})
	}
}
