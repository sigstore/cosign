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
	"io/ioutil"
	"os"

	"github.com/pkg/errors"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/xanzy/go-gitlab"
)

const (
	ReferenceScheme = "gitlab"
)

type Gl struct{}

func New() *Gl {
	return &Gl{}
}

func (g *Gl) PutSecret(ctx context.Context, ref string, pf cosign.PassFunc) error {
	keys, err := cosign.GenerateKeyPair(pf)
	if err != nil {
		return errors.Wrap(err, "generating key pair")
	}

	token, tokenExists := os.LookupEnv("GITLAB_TOKEN")

	if !tokenExists {
		return errors.New("could not find \"GITLAB_TOKEN\"")
	}

	var client *gitlab.Client
	if url, baseURLExists := os.LookupEnv("GITLAB_BASE_URL"); baseURLExists {
		client, err = gitlab.NewClient(token, gitlab.WithBaseURL(url))
		if err != nil {
			return errors.Wrap(err, "could not create GitLab client")
		}
	} else {
		client, err = gitlab.NewClient(token)
		if err != nil {
			return errors.Wrap(err, "could not create GitLab client")
		}
	}

	_, passwordResp, err := client.ProjectVariables.CreateVariable(ref, &gitlab.CreateProjectVariableOptions{
		Key:              gitlab.String("COSIGN_PASSWORD"),
		Value:            gitlab.String(string(keys.Password())),
		VariableType:     gitlab.VariableType(gitlab.EnvVariableType),
		Protected:        gitlab.Bool(false),
		Masked:           gitlab.Bool(false),
		EnvironmentScope: gitlab.String("*"),
	})
	if err != nil {
		return errors.Wrap(err, "could not create \"COSIGN_PASSWORD\" variable")
	}

	if passwordResp.StatusCode < 200 && passwordResp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(passwordResp.Body)
		return errors.Errorf("%s", bodyBytes)
	}

	fmt.Fprintln(os.Stderr, "Password written to \"COSIGN_PASSWORD\" variable")

	_, privateKeyResp, err := client.ProjectVariables.CreateVariable(ref, &gitlab.CreateProjectVariableOptions{
		Key:          gitlab.String("COSIGN_PRIVATE_KEY"),
		Value:        gitlab.String(string(keys.PrivateBytes)),
		VariableType: gitlab.VariableType(gitlab.EnvVariableType),
		Protected:    gitlab.Bool(false),
		Masked:       gitlab.Bool(false),
	})
	if err != nil {
		return errors.Wrap(err, "could not create \"COSIGN_PRIVATE_KEY\" variable")
	}

	if privateKeyResp.StatusCode < 200 && privateKeyResp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(privateKeyResp.Body)
		return errors.Errorf("%s", bodyBytes)
	}

	fmt.Fprintln(os.Stderr, "Private key written to \"COSIGN_PRIVATE_KEY\" variable")

	_, publicKeyResp, err := client.ProjectVariables.CreateVariable(ref, &gitlab.CreateProjectVariableOptions{
		Key:          gitlab.String("COSIGN_PUBLIC_KEY"),
		Value:        gitlab.String(string(keys.PublicBytes)),
		VariableType: gitlab.VariableType(gitlab.EnvVariableType),
		Protected:    gitlab.Bool(false),
		Masked:       gitlab.Bool(false),
	})
	if err != nil {
		return errors.Wrap(err, "could not create \"COSIGN_PUBLIC_KEY\" variable")
	}

	if publicKeyResp.StatusCode < 200 && publicKeyResp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(publicKeyResp.Body)
		return errors.Errorf("%s", bodyBytes)
	}

	fmt.Fprintln(os.Stderr, "Public key written to \"COSIGN_PUBLIC_KEY\" variable")

	if err := ioutil.WriteFile("cosign.pub", keys.PublicBytes, 0o600); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Public key also written to cosign.pub")

	return nil
}
