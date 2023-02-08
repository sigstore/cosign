package gitlab

import (
	"context"

	"github.com/sigstore/cosign/v2/pkg/cosign/env"
	"github.com/sigstore/cosign/v2/pkg/providers"
)

func init() {
	providers.Register("gitlab-runner", &gitlabRunner{})
}

type gitlabRunner struct{}

var _ providers.Interface = (*gitlabRunner)(nil)

// Enabled implements providers.Interface
func (ga *gitlabRunner) Enabled(ctx context.Context) bool {
	return env.Getenv(env.VariableGitLabJWTToken) != ""
}

// Provide implements providers.Interface
func (ga *gitlabRunner) Provide(ctx context.Context, audience string) (string, error) {
	token := env.Getenv(env.VariableGitLabJWTToken)
	return token, nil
}
