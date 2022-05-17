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
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/google/go-github/v42/github"
	"golang.org/x/oauth2"

	"github.com/sigstore/cosign/pkg/cosign"
)

const (
	ReferenceScheme = "github"
)

type Gh struct{}

func New() *Gh {
	return &Gh{}
}

func (g *Gh) PutSecret(ctx context.Context, ref string, pf cosign.PassFunc) error {
	keys, err := cosign.GenerateKeyPair(pf)
	if err != nil {
		return fmt.Errorf("generating key pair: %w", err)
	}

	var httpClient *http.Client
	if token, ok := os.LookupEnv("GITHUB_TOKEN"); ok {
		ts := oauth2.StaticTokenSource(
			&oauth2.Token{AccessToken: token},
		)
		httpClient = oauth2.NewClient(ctx, ts)
	} else {
		return errors.New("could not find \"GITHUB_TOKEN\" env variable")
	}
	client := github.NewClient(httpClient)

	split := strings.Split(ref, "/")
	if len(split) < 2 {
		return errors.New("could not parse scheme, use github://<owner>/<repo> format")
	}
	owner, repo := split[0], split[1]

	key, getRepoPubKeyResp, err := client.Actions.GetRepoPublicKey(ctx, owner, repo)
	if err != nil {
		return fmt.Errorf("could not get repository public key: %w", err)
	}

	if getRepoPubKeyResp.StatusCode < 200 && getRepoPubKeyResp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(getRepoPubKeyResp.Body)
		return fmt.Errorf("%s", bodyBytes)
	}

	passwordSecretEnv := &github.EncryptedSecret{
		Name:           "COSIGN_PASSWORD",
		KeyID:          key.GetKeyID(),
		EncryptedValue: base64.StdEncoding.EncodeToString(keys.Password()),
	}

	passwordSecretEnvResp, err := client.Actions.CreateOrUpdateRepoSecret(ctx, owner, repo, passwordSecretEnv)
	if err != nil {
		return fmt.Errorf("could not create \"COSIGN_PASSWORD\" github actions secret: %w", err)
	}

	if passwordSecretEnvResp.StatusCode < 200 && passwordSecretEnvResp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(passwordSecretEnvResp.Body)
		return fmt.Errorf("%s", bodyBytes)
	}

	fmt.Fprintln(os.Stderr, "Password written to COSIGN_PASSWORD github actions secret")

	privateKeySecretEnv := &github.EncryptedSecret{
		Name:           "COSIGN_PRIVATE_KEY",
		KeyID:          key.GetKeyID(),
		EncryptedValue: base64.StdEncoding.EncodeToString(keys.PrivateBytes),
	}

	privateKeySecretEnvResp, err := client.Actions.CreateOrUpdateRepoSecret(ctx, owner, repo, privateKeySecretEnv)
	if err != nil {
		return fmt.Errorf("could not create \"COSIGN_PRIVATE_KEY\" github actions secret: %w", err)
	}

	if privateKeySecretEnvResp.StatusCode < 200 && privateKeySecretEnvResp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(privateKeySecretEnvResp.Body)
		return fmt.Errorf("%s", bodyBytes)
	}

	fmt.Fprintln(os.Stderr, "Private key written to COSIGN_PRIVATE_KEY github actions secret")

	publicKeySecretEnv := &github.EncryptedSecret{
		Name:           "COSIGN_PUBLIC_KEY",
		KeyID:          key.GetKeyID(),
		EncryptedValue: base64.StdEncoding.EncodeToString(keys.PublicBytes),
	}

	publicKeySecretEnvResp, err := client.Actions.CreateOrUpdateRepoSecret(ctx, owner, repo, publicKeySecretEnv)
	if err != nil {
		return fmt.Errorf("could not create \"COSIGN_PUBLIC_KEY\" github actions secret: %w", err)
	}

	if publicKeySecretEnvResp.StatusCode < 200 && publicKeySecretEnvResp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(publicKeySecretEnvResp.Body)
		return fmt.Errorf("%s", bodyBytes)
	}

	fmt.Fprintln(os.Stderr, "Public key written to COSIGN_PUBLIC_KEY github actions secret")

	if err := os.WriteFile("cosign.pub", keys.PublicBytes, 0o600); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Public key also written to cosign.pub")

	return nil
}

// NOTE: GetSecret is not implemented for GitHub
func (g *Gh) GetSecret(ctx context.Context, ref string, key string) (string, error) {
	return "", nil
}
