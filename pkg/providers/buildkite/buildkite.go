// Copyright 2023 The Sigstore Authors.
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

package buildkite

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/buildkite/agent/v3/api"
	"github.com/buildkite/agent/v3/logger"
	"github.com/sigstore/cosign/v2/pkg/cosign/env"
	"github.com/sigstore/cosign/v2/pkg/providers"
)

func init() {
	providers.Register("buildkite-agent", &buildkiteAgent{})
}

type buildkiteAgent struct{}

var _ providers.Interface = (*buildkiteAgent)(nil)

// Enabled implements providers.Interface
func (ba *buildkiteAgent) Enabled(_ context.Context) bool {
	return env.Getenv(env.VariableBuildkiteAgentAccessToken) != ""
}

// Provide implements providers.Interface
func (ba *buildkiteAgent) Provide(ctx context.Context, audience string) (string, error) {
	agentToken := env.Getenv(env.VariableBuildkiteAgentAccessToken)
	endpoint := env.Getenv(env.VariableBuildkiteAgentEndpoint)
	if endpoint == "" {
		endpoint = "https://agent.buildkite.com/v3"
	}
	jobID := env.Getenv(env.VariableBuildkiteJobID)
	logLevel := env.Getenv(env.VariableBuildkiteAgentLogLevel)
	if logLevel == "" {
		logLevel = "notice"
	}

	l := logger.NewConsoleLogger(logger.NewTextPrinter(os.Stderr), os.Exit)
	level, err := logger.LevelFromString(logLevel)
	if err != nil {
		return "", err
	}
	l.SetLevel(level)

	client := api.NewClient(l, api.Config{Token: agentToken, Endpoint: endpoint})
	token, response, err := client.OIDCToken(ctx, &api.OIDCTokenRequest{Audience: audience, Job: jobID})
	if err != nil {
		return "", err
	}
	if response != nil && response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("buildkite agent request failed with status: %s", response.Status)
	}
	return token.Token, nil
}
