package git

import (
	"context"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/git/github"
)

var providerMap = map[string]Git{
	github.GitHubReference: github.New(),
}

type Git interface {
	PutSecret(ctx context.Context, ref string, pf cosign.PassFunc) error
}

func GetGit(provider string) Git {
	return providerMap[provider]
}
