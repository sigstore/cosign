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

package gitlab

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/sigstore/cosign/v3/internal/ui"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/cosign/env"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

const (
	ReferenceScheme = "gitlab"
)

type Gl struct{}

func New() *Gl {
	return &Gl{}
}

// isGroup checks if the given reference is a GitLab group by attempting to retrieve it.
// It returns true if the reference is a group, false if it's a project, and an error if neither.
func isGroup(client *gitlab.Client, ref string) (bool, error) {
	// Try to get as a project first (most common case)
	_, resp, err := client.Projects.GetProject(ref, nil)
	if err == nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return false, nil
	}

	// If project lookup failed, try as a group
	_, resp, err = client.Groups.GetGroup(ref, nil)
	if err == nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return true, nil
	}

	// Neither project nor group found
	return false, fmt.Errorf("reference %q is neither a valid project nor group", ref)
}

func (g *Gl) PutSecret(ctx context.Context, ref string, pf cosign.PassFunc) error {
	keys, err := cosign.GenerateKeyPair(pf)
	if err != nil {
		return fmt.Errorf("generating key pair: %w", err)
	}

	token, tokenExists := env.LookupEnv(env.VariableGitLabToken)

	if !tokenExists {
		return fmt.Errorf("could not find %q", env.VariableGitLabToken.String())
	}

	var client *gitlab.Client
	if url, baseURLExists := env.LookupEnv(env.VariableGitLabHost); baseURLExists {
		client, err = gitlab.NewClient(token, gitlab.WithBaseURL(url))
		if err != nil {
			return fmt.Errorf("could not create GitLab client: %w", err)
		}
	} else {
		client, err = gitlab.NewClient(token)
		if err != nil {
			return fmt.Errorf("could not create GitLab client: %w", err)
		}
	}

	// Determine if ref is a group or project
	isGrp, err := isGroup(client, ref)
	if err != nil {
		ui.Warnf(ctx, "If you are using a self-hosted gitlab please set the \"GITLAB_HOST\" your server name.")
		return fmt.Errorf("could not determine if reference is a group or project: %w", err)
	}

	var refType string
	if isGrp {
		refType = "group"
	} else {
		refType = "project"
	}

	// Create COSIGN_PASSWORD variable
	if isGrp {
		_, passwordResp, err := client.GroupVariables.CreateVariable(ref, &gitlab.CreateGroupVariableOptions{
			Key:              gitlab.Ptr("COSIGN_PASSWORD"),
			Value:            gitlab.Ptr(string(keys.Password())),
			VariableType:     gitlab.Ptr(gitlab.EnvVariableType),
			Protected:        gitlab.Ptr(false),
			Masked:           gitlab.Ptr(false),
			EnvironmentScope: gitlab.Ptr("*"),
		})
		if err != nil {
			return fmt.Errorf("could not create \"COSIGN_PASSWORD\" variable: %w", err)
		}
		if passwordResp.StatusCode < 200 || passwordResp.StatusCode >= 300 {
			bodyBytes, _ := io.ReadAll(passwordResp.Body)
			return fmt.Errorf("%s", bodyBytes)
		}
	} else {
		_, passwordResp, err := client.ProjectVariables.CreateVariable(ref, &gitlab.CreateProjectVariableOptions{
			Key:              gitlab.Ptr("COSIGN_PASSWORD"),
			Value:            gitlab.Ptr(string(keys.Password())),
			VariableType:     gitlab.Ptr(gitlab.EnvVariableType),
			Protected:        gitlab.Ptr(false),
			Masked:           gitlab.Ptr(false),
			EnvironmentScope: gitlab.Ptr("*"),
		})
		if err != nil {
			return fmt.Errorf("could not create \"COSIGN_PASSWORD\" variable: %w", err)
		}
		if passwordResp.StatusCode < 200 || passwordResp.StatusCode >= 300 {
			bodyBytes, _ := io.ReadAll(passwordResp.Body)
			return fmt.Errorf("%s", bodyBytes)
		}
	}

	ui.Infof(ctx, "Password written to \"COSIGN_PASSWORD\" %s variable", refType)

	// Create COSIGN_PRIVATE_KEY variable
	if isGrp {
		_, privateKeyResp, err := client.GroupVariables.CreateVariable(ref, &gitlab.CreateGroupVariableOptions{
			Key:          gitlab.Ptr("COSIGN_PRIVATE_KEY"),
			Value:        gitlab.Ptr(string(keys.PrivateBytes)),
			VariableType: gitlab.Ptr(gitlab.EnvVariableType),
			Protected:    gitlab.Ptr(false),
			Masked:       gitlab.Ptr(false),
		})
		if err != nil {
			return fmt.Errorf("could not create \"COSIGN_PRIVATE_KEY\" variable: %w", err)
		}
		if privateKeyResp.StatusCode < 200 || privateKeyResp.StatusCode >= 300 {
			bodyBytes, _ := io.ReadAll(privateKeyResp.Body)
			return fmt.Errorf("%s", bodyBytes)
		}
	} else {
		_, privateKeyResp, err := client.ProjectVariables.CreateVariable(ref, &gitlab.CreateProjectVariableOptions{
			Key:          gitlab.Ptr("COSIGN_PRIVATE_KEY"),
			Value:        gitlab.Ptr(string(keys.PrivateBytes)),
			VariableType: gitlab.Ptr(gitlab.EnvVariableType),
			Protected:    gitlab.Ptr(false),
			Masked:       gitlab.Ptr(false),
		})
		if err != nil {
			return fmt.Errorf("could not create \"COSIGN_PRIVATE_KEY\" variable: %w", err)
		}
		if privateKeyResp.StatusCode < 200 || privateKeyResp.StatusCode >= 300 {
			bodyBytes, _ := io.ReadAll(privateKeyResp.Body)
			return fmt.Errorf("%s", bodyBytes)
		}
	}

	ui.Infof(ctx, "Private key written to \"COSIGN_PRIVATE_KEY\" %s variable", refType)

	// Create COSIGN_PUBLIC_KEY variable
	if isGrp {
		_, publicKeyResp, err := client.GroupVariables.CreateVariable(ref, &gitlab.CreateGroupVariableOptions{
			Key:          gitlab.Ptr("COSIGN_PUBLIC_KEY"),
			Value:        gitlab.Ptr(string(keys.PublicBytes)),
			VariableType: gitlab.Ptr(gitlab.EnvVariableType),
			Protected:    gitlab.Ptr(false),
			Masked:       gitlab.Ptr(false),
		})
		if err != nil {
			return fmt.Errorf("could not create \"COSIGN_PUBLIC_KEY\" variable: %w", err)
		}
		if publicKeyResp.StatusCode < 200 || publicKeyResp.StatusCode >= 300 {
			bodyBytes, _ := io.ReadAll(publicKeyResp.Body)
			return fmt.Errorf("%s", bodyBytes)
		}
	} else {
		_, publicKeyResp, err := client.ProjectVariables.CreateVariable(ref, &gitlab.CreateProjectVariableOptions{
			Key:          gitlab.Ptr("COSIGN_PUBLIC_KEY"),
			Value:        gitlab.Ptr(string(keys.PublicBytes)),
			VariableType: gitlab.Ptr(gitlab.EnvVariableType),
			Protected:    gitlab.Ptr(false),
			Masked:       gitlab.Ptr(false),
		})
		if err != nil {
			return fmt.Errorf("could not create \"COSIGN_PUBLIC_KEY\" variable: %w", err)
		}
		if publicKeyResp.StatusCode < 200 || publicKeyResp.StatusCode >= 300 {
			bodyBytes, _ := io.ReadAll(publicKeyResp.Body)
			return fmt.Errorf("%s", bodyBytes)
		}
	}

	ui.Infof(ctx, "Public key written to \"COSIGN_PUBLIC_KEY\" %s variable", refType)

	if err := os.WriteFile("cosign.pub", keys.PublicBytes, 0o600); err != nil {
		return err
	}
	ui.Infof(ctx, "Public key also written to cosign.pub")

	return nil
}

func (g *Gl) GetSecret(_ context.Context, ref string, key string) (string, error) {
	token, tokenExists := env.LookupEnv(env.VariableGitLabToken)
	var varValue string
	if !tokenExists {
		return varValue, fmt.Errorf("could not find %q", env.VariableGitLabToken.String())
	}

	var client *gitlab.Client
	var err error
	if url, baseURLExists := env.LookupEnv(env.VariableGitLabHost); baseURLExists {
		client, err = gitlab.NewClient(token, gitlab.WithBaseURL(url))
		if err != nil {
			return varValue, fmt.Errorf("could not create GitLab client): %w", err)
		}
	} else {
		client, err = gitlab.NewClient(token)
		if err != nil {
			return varValue, fmt.Errorf("could not create GitLab client: %w", err)
		}
	}

	// Determine if ref is a group or project
	isGrp, err := isGroup(client, ref)
	if err != nil {
		return varValue, fmt.Errorf("could not determine if reference is a group or project: %w", err)
	}

	// Get variable based on reference type
	if isGrp {
		groupVar, resp, err := client.GroupVariables.GetVariable(ref, key, nil)
		if err != nil {
			return varValue, fmt.Errorf("could not retrieve %q group variable: %w", key, err)
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			bodyBytes, _ := io.ReadAll(resp.Body)
			return varValue, fmt.Errorf("%s", bodyBytes)
		}
		varValue = groupVar.Value
	} else {
		projectVar, resp, err := client.ProjectVariables.GetVariable(ref, key, nil)
		if err != nil {
			return varValue, fmt.Errorf("could not retrieve %q project variable: %w", key, err)
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			bodyBytes, _ := io.ReadAll(resp.Body)
			return varValue, fmt.Errorf("%s", bodyBytes)
		}
		varValue = projectVar.Value
	}

	return varValue, nil
}
