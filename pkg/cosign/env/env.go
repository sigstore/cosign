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
			Sensitive:   false,
		},
		VariableDockerMediaTypes: {
			Description: "to be used with registries that do not support OCI media types",
			Sensitive:   false,
		},
		VariablePassword: {
			Description: "overrides password inputs with this value",
			Sensitive:   true,
		},
		VariablePKCS11Pin: {
			Description: "to be used if PKCS11 PIN is not provided",
			Sensitive:   true,
		},
		VariablePKCS11ModulePath: {
			Description: "is PKCS11 module-path",
			Sensitive:   false,
		},
		VariableRepository: {
			Description: "can be used to store signatures in an alternate location",
			Sensitive:   false,
		},
	}
)

func Getenv(name Variable) string {
	return os.Getenv(name.String())
}

func LookupEnv(name Variable) (string, bool) {
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
