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

	"github.com/sigstore/cosign/v2/internal/ui"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/env"
	"github.com/xanzy/go-gitlab"
)

const (
	ReferenceScheme = "gitlab"
)

type glContext uint8

const (
	contextProject glContext = iota
	contextGroup   glContext = iota
)

type Gl struct{}

func New() *Gl {
	return &Gl{}
}

func (g *Gl) getGitlabContext(client *gitlab.Client, ref string) (glContext, error) {
	_, resp, err := client.Projects.GetProject(ref, &gitlab.GetProjectOptions{})
	if err == nil {
		return contextProject, nil
	} else if resp.StatusCode == 404 {
		_, _, err := client.Groups.GetGroup(ref, &gitlab.GetGroupOptions{})
		if err == nil {
			return contextGroup, nil
		} else {
			return contextGroup, err
		}
	} else {
		return contextProject, err
	}
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

	context, err := g.getGitlabContext(client, ref)
	if err != nil {
		return fmt.Errorf("cannot determine if \"%s\" is project or group: %w", ref, err)
	}

	var resp *gitlab.Response

	if context == contextProject {
		_, resp, err = client.ProjectVariables.CreateVariable(ref, &gitlab.CreateProjectVariableOptions{
			Key:              gitlab.Ptr("COSIGN_PASSWORD"),
			Value:            gitlab.Ptr(string(keys.Password())),
			VariableType:     gitlab.Ptr(gitlab.EnvVariableType),
			Protected:        gitlab.Ptr(false),
			Masked:           gitlab.Ptr(false),
			EnvironmentScope: gitlab.Ptr("*"),
		})
	} else if context == contextGroup {
		_, resp, err = client.GroupVariables.CreateVariable(ref, &gitlab.CreateGroupVariableOptions{
			Key:              gitlab.Ptr("COSIGN_PASSWORD"),
			Value:            gitlab.Ptr(string(keys.Password())),
			VariableType:     gitlab.Ptr(gitlab.EnvVariableType),
			Protected:        gitlab.Ptr(false),
			Masked:           gitlab.Ptr(false),
			EnvironmentScope: gitlab.Ptr("*"),
		})
	}
	if err != nil {
		ui.Warnf(ctx, "If you are using a self-hosted gitlab please set the \"GITLAB_HOST\" your server name.")
		return fmt.Errorf("could not create \"COSIGN_PASSWORD\" variable: %w", err)
	}

	if resp.StatusCode < 200 && resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s", bodyBytes)
	}

	ui.Infof(ctx, "Password written to \"COSIGN_PASSWORD\" variable")

	if context == contextProject {
		_, resp, err = client.ProjectVariables.CreateVariable(ref, &gitlab.CreateProjectVariableOptions{
			Key:          gitlab.Ptr("COSIGN_PRIVATE_KEY"),
			Value:        gitlab.Ptr(string(keys.PrivateBytes)),
			VariableType: gitlab.Ptr(gitlab.EnvVariableType),
			Protected:    gitlab.Ptr(false),
			Masked:       gitlab.Ptr(false),
		})
	} else if context == contextGroup {
		_, resp, err = client.GroupVariables.CreateVariable(ref, &gitlab.CreateGroupVariableOptions{
			Key:          gitlab.Ptr("COSIGN_PRIVATE_KEY"),
			Value:        gitlab.Ptr(string(keys.PrivateBytes)),
			VariableType: gitlab.Ptr(gitlab.EnvVariableType),
			Protected:    gitlab.Ptr(false),
			Masked:       gitlab.Ptr(false),
		})

	}
	if err != nil {
		return fmt.Errorf("could not create \"COSIGN_PRIVATE_KEY\" variable: %w", err)
	}

	if resp.StatusCode < 200 && resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s", bodyBytes)
	}

	ui.Infof(ctx, "Private key written to \"COSIGN_PRIVATE_KEY\" variable")

	if context == contextProject {
		_, resp, err = client.ProjectVariables.CreateVariable(ref, &gitlab.CreateProjectVariableOptions{
			Key:          gitlab.Ptr("COSIGN_PUBLIC_KEY"),
			Value:        gitlab.Ptr(string(keys.PublicBytes)),
			VariableType: gitlab.Ptr(gitlab.EnvVariableType),
			Protected:    gitlab.Ptr(false),
			Masked:       gitlab.Ptr(false),
		})
	} else if context == contextGroup {
		_, resp, err = client.GroupVariables.CreateVariable(ref, &gitlab.CreateGroupVariableOptions{
			Key:          gitlab.Ptr("COSIGN_PUBLIC_KEY"),
			Value:        gitlab.Ptr(string(keys.PublicBytes)),
			VariableType: gitlab.Ptr(gitlab.EnvVariableType),
			Protected:    gitlab.Ptr(false),
			Masked:       gitlab.Ptr(false),
		})

	}
	if err != nil {
		return fmt.Errorf("could not create \"COSIGN_PUBLIC_KEY\" variable: %w", err)
	}

	if resp.StatusCode < 200 && resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s", bodyBytes)
	}

	ui.Infof(ctx, "Public key written to \"COSIGN_PUBLIC_KEY\" variable")

	if err := os.WriteFile("cosign.pub", keys.PublicBytes, 0o600); err != nil {
		return err
	}
	ui.Infof(ctx, "Public key also written to cosign.pub")

	return nil
}

func (g *Gl) GetSecret(_ context.Context, ref string, key string) (string, error) {
	token, tokenExists := env.LookupEnv(env.VariableGitLabToken)
	var varKeyValue string
	if !tokenExists {
		return varKeyValue, fmt.Errorf("could not find %q", env.VariableGitLabToken.String())
	}

	var client *gitlab.Client
	var err error
	if url, baseURLExists := env.LookupEnv(env.VariableGitLabHost); baseURLExists {
		client, err = gitlab.NewClient(token, gitlab.WithBaseURL(url))
		if err != nil {
			return varKeyValue, fmt.Errorf("could not create GitLab client): %w", err)
		}
	} else {
		client, err = gitlab.NewClient(token)
		if err != nil {
			return varKeyValue, fmt.Errorf("could not create GitLab client: %w", err)
		}
	}

	context, err := g.getGitlabContext(client, ref)
	if err != nil {
		return "", fmt.Errorf("cannot determine if \"%s\" is project or group: %w", ref, err)
	}

	var statusCode int
	var bodyBytes []byte

	if context == contextProject {
		varKey, resp, err := client.ProjectVariables.GetVariable(ref, key, nil)
		if err != nil {
			return "", fmt.Errorf("could not retrieve \"%s\" variable: %w", key, err)
		}
		varKeyValue = varKey.Value
		statusCode = resp.StatusCode
		bodyBytes, _ = io.ReadAll(resp.Body)
	} else if context == contextGroup {
		varKey, resp, err := client.GroupVariables.GetVariable(ref, key, nil)
		if err != nil {
			return "", fmt.Errorf("could not retrieve \"%s\" variable: %w", key, err)
		}
		varKeyValue = varKey.Value
		statusCode = resp.StatusCode
		bodyBytes, _ = io.ReadAll(resp.Body)
	}

	if statusCode < 200 && statusCode >= 300 {
		return varKeyValue, fmt.Errorf("%s", bodyBytes)
	}

	return varKeyValue, nil
}
