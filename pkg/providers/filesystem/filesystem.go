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

package filesystem

import (
	"context"
	"os"

	"github.com/sigstore/cosign/v3/pkg/providers"
)

func init() {
	providers.Register("filesystem", &filesystem{})
}

type filesystem struct{}

var _ providers.Interface = (*filesystem)(nil)

const (
	// FilesystemTokenPath is the default path to where we read an OIDC
	// token from the filesystem. Used when FilesystemTokenFileEnvVar is unset.
	// nolint
	FilesystemTokenPath = "/var/run/sigstore/cosign/oidc-token"

	// FilesystemTokenFileEnvVar, when set, overrides FilesystemTokenPath with
	// any user-writable location. This allows the filesystem provider to be
	// used on desktop / dev workstations without the one-time sudo step
	// required to create /var/run/sigstore/cosign.
	FilesystemTokenFileEnvVar = "SIGSTORE_OIDC_TOKEN_FILE"
)

// tokenPath returns the path the filesystem provider reads the OIDC token
// from: SIGSTORE_OIDC_TOKEN_FILE if set, else the historical default.
func tokenPath() string {
	if p := os.Getenv(FilesystemTokenFileEnvVar); p != "" {
		return p
	}
	return FilesystemTokenPath
}

// Enabled implements providers.Interface
func (ga *filesystem) Enabled(_ context.Context) bool {
	// If we can stat the file without error then this is enabled.
	_, err := os.Stat(tokenPath())
	return err == nil
}

// Provide implements providers.Interface
func (ga *filesystem) Provide(ctx context.Context, audience string) (string, error) { //nolint: revive
	b, err := os.ReadFile(tokenPath())
	if err != nil {
		return "", err
	}
	return string(b), nil
}
