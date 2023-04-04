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

package spiffe

import (
	"context"
	"os"

	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"

	"github.com/sigstore/cosign/v2/pkg/cosign/env"
	"github.com/sigstore/cosign/v2/pkg/providers"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func init() {
	providers.Register("spiffe", &spiffe{})
}

type spiffe struct{}

var _ providers.Interface = (*spiffe)(nil)

const (
	// defaultSocketPath is the path to where we read an OIDC
	// token from the spiffe by default.
	// nolint
	defaultSocketPath = "/tmp/spire-agent/public/api.sock"
)

// getSocketPath gets which Spiffe socket to use. Either default
// or the one specified by environment variable.
func getSocketPath() string {
	if env := env.Getenv(env.VariableSPIFFEEndpointSocket); env != "" {
		return env
	}
	return defaultSocketPath
}

// Enabled implements providers.Interface
func (ga *spiffe) Enabled(_ context.Context) bool {
	// If we can stat the file without error then this is enabled.
	_, err := os.Stat(getSocketPath())
	return err == nil
}

// Provide implements providers.Interface
func (ga *spiffe) Provide(ctx context.Context, audience string) (string, error) {
	// Creates a new Workload API client, connecting to provided socket path
	// Environment variable `SPIFFE_ENDPOINT_SOCKET` is used if given and
	// defaultSocketPath if not.
	client, err := workloadapi.New(ctx, workloadapi.WithAddr("unix://"+getSocketPath()))
	if err != nil {
		return "", err
	}
	defer client.Close()

	svid, err := client.FetchJWTSVID(ctx, jwtsvid.Params{
		Audience: audience,
	})
	if err != nil {
		return "", err
	}

	return svid.Marshal(), nil
}
