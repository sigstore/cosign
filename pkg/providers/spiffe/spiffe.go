package spiffe

import (
	"context"
	"os"

	"github.com/pkg/errors"
	"github.com/sigstore/cosign/pkg/providers"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func init() {
	providers.Register("spiffe", &spiffe{})
}

type spiffe struct{}

var _ providers.Interface = (*spiffe)(nil)

const (
	// socketPath is the path to where we read an OIDC
	// token from the spiffe.
	// nolint
	socketPath = "/run/spire-sockets/api.sock"
)

// Enabled implements providers.Interface
func (ga *spiffe) Enabled(ctx context.Context) bool {
	// If we can stat the file without error then this is enabled.
	_, err := os.Stat(socketPath)
	return err == nil
}

// Provide implements providers.Interface
func (ga *spiffe) Provide(ctx context.Context, audience string) (string, error) {
	svidCtx, err := workloadapi.FetchX509Context(ctx, workloadapi.WithAddr(socketPath))
	if err != nil {
		return "", err
	}

	svid := svidCtx.DefaultSVID()
	if len(svid.Certificates) <= 0 {
		return "", errors.New("could not found certificates")
	}

	if svid.PrivateKey == nil {
		return "", errors.New("could not found private key")
	}

	return svid.ID.String(), nil
}
