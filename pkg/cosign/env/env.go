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
	"fmt"
	"os"
	"sort"
	"strings"
)

type Variable string

type VariableOpts struct {
	Description string
	Expects     string
	Sensitive   bool
}

func (v Variable) String() string {
	return string(v)
}

const (
	VariableExperimental     Variable = "COSIGN_EXPERIMENTAL"
	VariableDockerMediaTypes Variable = "COSIGN_DOCKER_MEDIA_TYPES"
	VariablePassword         Variable = "COSIGN_PASSWORD"
	VariablePKCS11Pin        Variable = "COSIGN_PKCS11_PIN"
	VariablePKCS11ModulePath Variable = "COSIGN_PKCS11_MODULE_PATH"
	VariableRepository       Variable = "COSIGN_REPOSITORY"
)

var (
	environmentVariables = map[Variable]VariableOpts{
		VariableExperimental: {
			Description: "enables experimental cosign features",
			Expects:     "1 if experimental features should be enabled (0 by default)",
			Sensitive:   false,
		},
		VariableDockerMediaTypes: {
			Description: "to be used with registries that do not support OCI media types",
			Expects:     "1 to fallback to legacy OCI media types equivalents (0 by default)",
			Sensitive:   false,
		},
		VariablePassword: {
			Description: "overrides password inputs with this value",
			Expects:     "string with a password (asks on stdin by default)",
			Sensitive:   true,
		},
		VariablePKCS11Pin: {
			Description: "to be used if PKCS11 PIN is not provided",
			Expects:     "string with a PIN",
			Sensitive:   true,
		},
		VariablePKCS11ModulePath: {
			Description: "is PKCS11 module-path",
			Expects:     "string with a module-path",
			Sensitive:   false,
		},
		VariableRepository: {
			Description: "can be used to store signatures in an alternate location",
			Expects:     "string with a repository",
			Sensitive:   false,
		},
	}
)

func mustRegisterEnv(name Variable) {
	if _, ok := environmentVariables[name]; !ok {
		panic(fmt.Sprintf("environment variable %q is not registered in pkg/cosign/env", name.String()))
	}
	if !strings.HasPrefix(name.String(), "COSIGN_") {
		panic(fmt.Sprintf("environment varialbe %q must start with COSIGN_ prefix", name.String()))
	}
}

func Getenv(name Variable) string {
	mustRegisterEnv(name)

	return os.Getenv(name.String())
}

func LookupEnv(name Variable) (string, bool) {
	mustRegisterEnv(name)

	return os.LookupEnv(name.String())
}

func PrintEnv(showDescription, showSensitive bool) {
	// Sort keys to print them in predictable order
	keys := sortKeys()

	for _, env := range keys {
		opts := environmentVariables[env]

		// Get value of environment variable
		val := os.Getenv(env.String())

		// If showDescription is set, print description for that variable
		if showDescription {
			fmt.Printf("# %s %s\n", env.String(), opts.Description)
			fmt.Printf("# Expects: %s\n", opts.Expects)
		}

		// If variable is sensitive, and we don't want to show sensitive values,
		// print environment variable name and some asterisk symbols.
		// If sensitive variable isn't set or doesn't have any value, we'll just
		// print like non-sensitive variable
		if opts.Sensitive && !showSensitive && val != "" {
			fmt.Printf("%s=\"******\"\n", env.String())
		} else {
			fmt.Printf("%s=%q\n", env.String(), val)
		}
	}
}

func sortKeys() []Variable {
	keys := []Variable{}
	for k := range environmentVariables {
		keys = append(keys, k)
	}

	sort.Slice(keys, func(i, j int) bool {
		return strings.Compare(keys[i].String(), keys[j].String()) < 0
	})

	return keys
}
