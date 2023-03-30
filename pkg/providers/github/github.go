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

package github

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/sigstore/cosign/v2/pkg/cosign/env"
	"github.com/sigstore/cosign/v2/pkg/providers"
)

const (
	// Deprecated: use `env.VariableGitHubRequestToken` instead
	RequestTokenEnvKey = env.VariableGitHubRequestToken
	// Deprecated: use `env.VariableGitHubRequestURL` instead
	RequestURLEnvKey = env.VariableGitHubRequestURL
)

func init() {
	providers.Register("github-actions", &githubActions{})
}

type githubActions struct{}

var _ providers.Interface = (*githubActions)(nil)

// Enabled implements providers.Interface
func (ga *githubActions) Enabled(_ context.Context) bool {
	if env.Getenv(env.VariableGitHubRequestToken) == "" {
		return false
	}
	if env.Getenv(env.VariableGitHubRequestURL) == "" {
		return false
	}
	return true
}

// Provide implements providers.Interface
func (ga *githubActions) Provide(_ context.Context, audience string) (string, error) {
	url := env.Getenv(env.VariableGitHubRequestURL) + "&audience=" + audience

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Add("Authorization", "bearer "+env.Getenv(env.VariableGitHubRequestToken))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var payload struct {
		Value string `json:"value"`
	}

	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&payload); err != nil {
		return "", err
	}
	return payload.Value, nil
}
