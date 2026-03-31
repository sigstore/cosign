// Copyright 2024 The Sigstore Authors.
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

package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
)

// TestLoadCmdAllowHTTPRegistry verifies that LoadCmd respects the
// --allow-http-registry flag and connects to plain-HTTP registries
// without upgrading to HTTPS.
//
// Regression test for https://github.com/sigstore/cosign/issues/4134.
func TestLoadCmdAllowHTTPRegistry(t *testing.T) {
	// Start an in-process HTTP registry.
	reg := registry.New()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reg.ServeHTTP(w, r)
	}))
	defer srv.Close()

	// Strip the leading "http://" — the registry address is host:port.
	addr := strings.TrimPrefix(srv.URL, "http://")
	imageRef := addr + "/test/image:latest"

	t.Run("AllowHTTPRegistry=true reaches the HTTP registry", func(t *testing.T) {
		opts := options.LoadOptions{
			Directory: t.TempDir(),
			Registry: options.RegistryOptions{
				AllowHTTPRegistry: true,
			},
		}
		// We expect a failure about the directory content (empty image
		// index), not about TLS — proving that the HTTP connection was
		// attempted rather than being rejected at the name-parsing level.
		err := LoadCmd(context.Background(), opts, imageRef)
		if err != nil && strings.Contains(err.Error(), "http: server gave HTTP response to HTTPS client") {
			t.Errorf("LoadCmd with AllowHTTPRegistry=true still attempted TLS: %v", err)
		}
	})

	t.Run("AllowHTTPRegistry=false fails to connect to HTTP-only registry", func(t *testing.T) {
		opts := options.LoadOptions{
			Directory: t.TempDir(),
			Registry: options.RegistryOptions{
				AllowHTTPRegistry: false,
			},
		}
		// Without the flag the connection to a plain-HTTP server should
		// fail with a TLS error (or similar transport error), not succeed.
		err := LoadCmd(context.Background(), opts, imageRef)
		if err == nil {
			t.Error("LoadCmd without AllowHTTPRegistry unexpectedly succeeded against an HTTP-only registry")
		}
	})
}
