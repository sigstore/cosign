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
	"os"
	"testing"
)

func TestMustRegisterEnv(t *testing.T) {
	// Calling this should NOT panic
	mustRegisterEnv(VariableExperimental)
}

func TestMustRegisterEnvWithNonRegisteredEnv(t *testing.T) {
	// This test must panic because non-registered variable is not registered with cosign.
	// We fail if the test doesn't panic.
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected to panic, but panic did not happen")
		}
	}()
	mustRegisterEnv(Variable("non-registered"))
}

func TestMustRegisterEnvWithInvalidCosignEnvVar(t *testing.T) {
	// This test must panic because registered non-external variable doesn't start with COSIGN_.
	// We fail if the test doesn't panic.
	saveEnvs := environmentVariables
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected to panic, but panic did not happen")
		}
		environmentVariables = saveEnvs
	}()
	v := Variable("TEST")
	environmentVariables = map[Variable]VariableOpts{
		v: {
			External: false,
		},
	}
	mustRegisterEnv(v)
}

func TestGetenv(t *testing.T) {
	os.Setenv("COSIGN_EXPERIMENTAL", "1")
	if val := Getenv(VariableExperimental); val != "1" {
		t.Errorf("expected to get \"1\", but got %q", val)
	}
}

func TestGetenvUnset(t *testing.T) {
	os.Unsetenv("COSIGN_EXPERIMENTAL")
	if val := Getenv(VariableExperimental); val != "" {
		t.Errorf("expected to get \"\", but got %q", val)
	}
}

func TestLookupEnv(t *testing.T) {
	os.Setenv("COSIGN_EXPERIMENTAL", "1")
	val, f := LookupEnv(VariableExperimental)
	if !f {
		t.Errorf("expected to find %q, but it's not set", "COSIGN_EXPERIMENTAL")
	}
	if val != "1" {
		t.Errorf("expected to get value \"1\", but got %q", val)
	}
}

func TestLookupEnvEmpty(t *testing.T) {
	os.Setenv("COSIGN_EXPERIMENTAL", "")
	val, f := LookupEnv(VariableExperimental)
	if !f {
		t.Errorf("expected to find %q, but it's not set", "COSIGN_EXPERIMENTAL")
	}
	if val != "" {
		t.Errorf("expected to get value \"\", but got %q", val)
	}
}

func TestLookupEnvUnset(t *testing.T) {
	os.Unsetenv("COSIGN_EXPERIMENTAL")
	val, f := LookupEnv(VariableExperimental)
	if f {
		t.Errorf("expected to not find %q, but it's set to %q", "COSIGN_EXPERIMENTAL", val)
	}
}
