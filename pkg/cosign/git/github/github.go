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

	"github.com/google/go-github/v72/github"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/oauth2"

	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/env"
)

const (
	ReferenceScheme = "github"
)

type Gh struct{}

func New() *Gh {
	return &Gh{}
}

func (g *Gh) PutSecret(ctx context.Context, ref string, pf cosign.PassFunc) error {
	var httpClient *http.Client
	if token, ok := env.LookupEnv(env.VariableGitHubToken); ok {
		ts := oauth2.StaticTokenSource(
			&oauth2.Token{AccessToken: token},
		)
		httpClient = oauth2.NewClient(ctx, ts)
	} else {
		return fmt.Errorf("could not find %q environment variable", env.VariableGitHubToken.String())
	}

	var client *github.Client
	if host, ok := env.LookupEnv(env.VariableGitHubHost); ok {
		var err error
		client, err = github.NewClient(httpClient).WithEnterpriseURLs(host, host)
		if err != nil {
			return fmt.Errorf("could not create github enterprise client: %w", err)
		}
	} else {
		client = github.NewClient(httpClient)
	}

	keys, err := cosign.GenerateKeyPair(pf)
	if err != nil {
		return fmt.Errorf("generating key pair: %w", err)
	}

	var owner, repo string
	split := strings.Split(ref, "/")

	switch len(split) {
	case 2:
		owner, repo = split[0], split[1]
	case 1:
		owner = split[0]
	default:
		return errors.New("could not parse scheme, use github://<owner> or github://<owner>/<repo> format")
	}

	key, getPubKeyResp, err := getPublicKey(ctx, client, owner, repo)
	if err != nil {
		return fmt.Errorf("could not get repository public key: %w", err)
	}

	if getPubKeyResp.StatusCode < 200 && getPubKeyResp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(getPubKeyResp.Body)
		return fmt.Errorf("%s", bodyBytes)
	}

	encryptedCosignPasswd, err := encryptSecretWithPublicKey(key, "COSIGN_PASSWORD", keys.Password())
	if err != nil {
		return fmt.Errorf("could not encrypt the secret: %w", err)
	}

	passwordSecretEnvResp, err := createOrUpdateOrgSecret(ctx, client, owner, repo, encryptedCosignPasswd)
	if err != nil {
		return fmt.Errorf("could not create \"COSIGN_PASSWORD\" github actions secret: %w", err)
	}

	if passwordSecretEnvResp.StatusCode < 200 && passwordSecretEnvResp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(passwordSecretEnvResp.Body)
		return fmt.Errorf("%s", bodyBytes)
	}

	fmt.Fprintln(os.Stderr, "Password written to COSIGN_PASSWORD github actions secret")

	encryptedCosignPrivKey, err := encryptSecretWithPublicKey(key, "COSIGN_PRIVATE_KEY", keys.PrivateBytes)
	if err != nil {
		return fmt.Errorf("could not encrypt the secret: %w", err)
	}

	privateKeySecretEnvResp, err := createOrUpdateOrgSecret(ctx, client, owner, repo, encryptedCosignPrivKey)
	if err != nil {
		return fmt.Errorf("could not create \"COSIGN_PRIVATE_KEY\" github actions secret: %w", err)
	}

	if privateKeySecretEnvResp.StatusCode < 200 && privateKeySecretEnvResp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(privateKeySecretEnvResp.Body)
		return fmt.Errorf("%s", bodyBytes)
	}

	fmt.Fprintln(os.Stderr, "Private key written to COSIGN_PRIVATE_KEY github actions secret")

	encryptedCosignPubKey, err := encryptSecretWithPublicKey(key, "COSIGN_PUBLIC_KEY", keys.PublicBytes)
	if err != nil {
		return fmt.Errorf("could not encrypt the secret: %w", err)
	}

	publicKeySecretEnvResp, err := createOrUpdateOrgSecret(ctx, client, owner, repo, encryptedCosignPubKey)
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
func (g *Gh) GetSecret(ctx context.Context, ref string, key string) (string, error) { //nolint: revive
	return "", nil
}

func createOrUpdateOrgSecret(ctx context.Context, client *github.Client, owner string, repo string, encryptedCosignPasswd *github.EncryptedSecret) (*github.Response, error) {
	if len(repo) > 0 {
		return client.Actions.CreateOrUpdateRepoSecret(ctx, owner, repo, encryptedCosignPasswd)
	}
	return client.Actions.CreateOrUpdateOrgSecret(ctx, owner, encryptedCosignPasswd)
}

func getPublicKey(ctx context.Context, client *github.Client, owner string, repo string) (*github.PublicKey, *github.Response, error) {
	if len(repo) > 0 {
		return client.Actions.GetRepoPublicKey(ctx, owner, repo)
	}
	return client.Actions.GetOrgPublicKey(ctx, owner)
}

func encryptSecretWithPublicKey(publicKey *github.PublicKey, secretName string, secretValue []byte) (*github.EncryptedSecret, error) {
	decodedPubKey, err := base64.StdEncoding.DecodeString(publicKey.GetKey())
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}
	var peersPubKey [32]byte
	copy(peersPubKey[:], decodedPubKey[0:32])

	var rand io.Reader

	eBody, err := box.SealAnonymous(nil, secretValue, &peersPubKey, rand)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt body: %w", err)
	}

	encryptedString := base64.StdEncoding.EncodeToString(eBody)
	keyID := publicKey.GetKeyID()
	encryptedSecret := &github.EncryptedSecret{
		Name:           secretName,
		KeyID:          keyID,
		EncryptedValue: encryptedString,
	}

	return encryptedSecret, nil
}
