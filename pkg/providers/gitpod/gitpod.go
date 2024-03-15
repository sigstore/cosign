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

package gitpod

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"

	"github.com/sigstore/cosign/v2/pkg/cosign/env"
	"github.com/sigstore/cosign/v2/pkg/providers"
)

func init() {
	providers.Register("filesystem", &gitpod{})
}

type gitpod struct{}

var _ providers.Interface = (*gitpod)(nil)

// Enabled implements providers.Interface
func (ga *gitpod) Enabled(_ context.Context) bool {
	// Check we are in a Gitpod Workspace
	if env.Getenv(env.VariableGitpodWorkspaceId) != "" {

		//Check we are able to generate tokens with a verified email address
		output, err := exec.Command("gp", "idp", "token", "--audience", "example.org", "--decode").Output()
		if err != nil {
			return false
		}

		var token struct {
			Payload *struct {
				Email         *string `json:"email"`
				EmailVerified bool    `json:"email_verified"`
			} `json:"Payload"`
		}
		dec := json.NewDecoder(bytes.NewBuffer(output))
		if err := dec.Decode(&token); err != nil {
			return false
		}

		if token.Payload != nil {
			return token.Payload.Email != nil && token.Payload.EmailVerified
		}
	}
	return false
}

// Provide implements providers.Interface
func (ga *gitpod) Provide(ctx context.Context, audience string) (string, error) {
	token, err := exec.Command("gp", "idp", "token", "--audience", audience).Output()
	if err != nil {
		return "", err
	}
	return string(token), nil
}
