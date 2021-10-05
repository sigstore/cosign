package github

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/google/go-github/v39/github"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/pkg/cosign"
	"golang.org/x/oauth2"
	"io"
	"net/http"
	"os"
	"strings"
)

const (
	GitHubReference = "github"
)

type gh struct{}

func New() *gh {
	return &gh{}
}

func (g *gh) PutSecret(ctx context.Context, ref string, pf cosign.PassFunc) error {
	keys, err := cosign.GenerateKeyPair(pf)
	if err != nil {
		return errors.Wrap(err, "generating key pair")
	}

	var httpClient *http.Client
	if token, ok := os.LookupEnv("GITHUB_TOKEN"); ok { // todo: if not ok then return error
		ts := oauth2.StaticTokenSource(
			&oauth2.Token{AccessToken: token},
		)
		httpClient = oauth2.NewClient(ctx, ts)
	}
	client := github.NewClient(httpClient)

	split := strings.Split(ref, "/")
	owner, repo := split[0], split[1] // todo: check second element

	key, _, err := client.Actions.GetRepoPublicKey(ctx, owner, repo) // todo: check response status

	secret := &github.EncryptedSecret{
		Name:           "COSIGN_PRIVATE_KEY",
		KeyID:          key.GetKeyID(),
		EncryptedValue: base64.StdEncoding.EncodeToString(keys.PrivateBytes),
	}

	repoSecret, err := client.Actions.CreateOrUpdateRepoSecret(ctx, owner, repo, secret)
	if err != nil {
		return err
	}

	if repoSecret.StatusCode < 200 && repoSecret.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(repoSecret.Body)
		return fmt.Errorf("%s", bodyBytes)
	}

	return nil
}
