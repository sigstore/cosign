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

// Variable is a type representing an environment variable
type Variable string

// VariableOpts closely describes a Variable
type VariableOpts struct {
	// Description contains description for the environment variable
	Description string
	// Expects describes what value is expected by the environment variable
	Expects string
	// Sensitive is used for environment variables with sensitive values
	// (e.g. passwords, credentials, etc.)
	Sensitive bool
	// External is used for environment variables coming from external projects
	// and dependencies (e.g. GITHUB_TOKEN, SIGSTORE_, TUF_)
	External bool
}

func (v Variable) String() string {
	return string(v)
}

const (
	// Cosign environment variables
	VariableExperimental     Variable = "COSIGN_EXPERIMENTAL"
	VariableDockerMediaTypes Variable = "COSIGN_DOCKER_MEDIA_TYPES"
	VariablePassword         Variable = "COSIGN_PASSWORD"
	VariablePKCS11Pin        Variable = "COSIGN_PKCS11_PIN"
	VariablePKCS11ModulePath Variable = "COSIGN_PKCS11_MODULE_PATH"
	VariableRepository       Variable = "COSIGN_REPOSITORY"

	// Sigstore environment variables
	VariableSigstoreCTLogPublicKeyFile  Variable = "SIGSTORE_CT_LOG_PUBLIC_KEY_FILE"
	VariableSigstoreRootFile            Variable = "SIGSTORE_ROOT_FILE"
	VariableSigstoreTrustRekorPublicKey Variable = "SIGSTORE_TRUST_REKOR_API_PUBLIC_KEY"
	VariableSigstoreRekorPublicKey      Variable = "SIGSTORE_REKOR_PUBLIC_KEY"

	// Other external environment variables
	VariableGitHubToken              Variable = "GITHUB_TOKEN" //nolint:gosec
	VariableGitHubRequestToken       Variable = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"
	VariableGitHubRequestURL         Variable = "ACTIONS_ID_TOKEN_REQUEST_URL"
	VariableSPIFFEEndpointSocket     Variable = "SPIFFE_ENDPOINT_SOCKET"
	VariableGoogleServiceAccountName Variable = "GOOGLE_SERVICE_ACCOUNT_NAME"
	VariableGitLabHost               Variable = "GITLAB_HOST"
	VariableGitLabToken              Variable = "GITLAB_TOKEN"
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

		VariableSigstoreCTLogPublicKeyFile: {
			Description: "overrides what is used to validate the SCT coming back from Fulcio",
			Expects:     "path to the public key file",
			Sensitive:   false,
			External:    true,
		},
		VariableSigstoreRootFile: {
			Description: "overrides the public good instance root CA",
			Expects:     "path to the root CA",
			Sensitive:   false,
			External:    true,
		},
		VariableSigstoreTrustRekorPublicKey: {
			Description: "if specified, will fetch the Rekor Public Key from the specified Rekor server and add it to RekorPubKeys. This env var is only for testing!",
			Expects:     "any string to trigger this behavior",
			Sensitive:   false,
			External:    true,
		},
		VariableSigstoreRekorPublicKey: {
			Description: "if specified, you can specify an oob Public Key that Rekor uses",
			Expects:     "path to the public key",
			Sensitive:   false,
			External:    true,
		},

		VariableGitHubToken: {
			Description: "is a token used to authenticate with GitHub",
			Expects:     "token generated on GitHub",
			Sensitive:   true,
			External:    true,
		},
		VariableGitHubRequestToken: {
			Description: "is bearer token for the request to the OIDC provider",
			Expects:     "string with a bearer token",
			Sensitive:   true,
			External:    true,
		},
		VariableGitHubRequestURL: {
			Description: "is the URL for GitHub's OIDC provider",
			Expects:     "string with the URL for the OIDC provider",
			Sensitive:   false,
			External:    true,
		},
		VariableSPIFFEEndpointSocket: {
			Description: "allows you to specify non-default SPIFFE socket to use.",
			Expects:     "string with SPIFFE socket path",
			Sensitive:   false,
			External:    true,
		},
		VariableGoogleServiceAccountName: {
			Description: "is a service account name to be used with the Google provider",
			Expects:     "string with the service account's name",
			Sensitive:   false,
			External:    false,
		},
		VariableGitLabHost: {
			Description: "is URL of the GitLab instance",
			Expects:     "string with the URL of GitLab instance",
			Sensitive:   false,
			External:    true,
		},
		VariableGitLabToken: {
			Description: "is a token used to authenticate with GitLab",
			Expects:     "string with a token",
			Sensitive:   true,
			External:    true,
		},
	}
)

func mustRegisterEnv(name Variable) {
	opts, ok := environmentVariables[name]
	if !ok {
		panic(fmt.Sprintf("environment variable %q is not registered in pkg/cosign/env", name.String()))
	}
	if !opts.External && !strings.HasPrefix(name.String(), "COSIGN_") {
		panic(fmt.Sprintf("cosign environment variable %q must start with COSIGN_ prefix", name.String()))
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
