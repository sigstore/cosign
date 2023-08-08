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
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

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
func (ga *githubActions) Provide(ctx context.Context, audience string) (string, error) {
	url := env.Getenv(env.VariableGitHubRequestURL) + "&audience=" + audience

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}

	// May be replaced by a different client if we hit HTTP_1_1_REQUIRED.
	client := http.DefaultClient

	// Retry up to 3 times.
	for i := 0; ; i++ {
		req.Header.Add("Authorization", "bearer "+env.Getenv(env.VariableGitHubRequestToken))
		resp, err := client.Do(req)
		if err != nil {
			if i == 2 {
				return "", err
			}

			// This error isn't exposed by net/http, and retrying this with the
			// DefaultClient will fail because it will just use HTTP2 again.
			// I don't know why go doesn't do this for us.
			if strings.Contains(err.Error(), "HTTP_1_1_REQUIRED") {
				http1transport := http.DefaultTransport.(*http.Transport).Clone()
				http1transport.ForceAttemptHTTP2 = false

				client = &http.Client{
					Transport: http1transport,
				}
			}

			fmt.Fprintf(os.Stderr, "error fetching GitHub OIDC token (will retry): %v\n", err)
			time.Sleep(time.Second)
			continue
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
}
