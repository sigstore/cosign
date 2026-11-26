//
// Copyright 2026 The Sigstore Authors.
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

//go:build e2e

package test

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
)

// TestE2E_ContainersAuthFallback demonstrates that when a Docker config exists on disk
// without credentials for a registry, authn.DefaultKeychain fails with 401 Unauthorized,
// while Cosign's DefaultContainersKeychain successfully authenticates via containers auth
// files (REGISTRY_AUTH_FILE and containers/auth.json).
func TestE2E_ContainersAuthFallback(t *testing.T) {
	regHandler := registry.New()
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != "testuser" || p != "testpass" {
			w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		regHandler.ServeHTTP(w, r)
	}))
	defer authServer.Close()

	u, err := url.Parse(authServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	regHost := u.Host
	target, err := name.NewRegistry(regHost, name.Insecure)
	if err != nil {
		t.Fatal(err)
	}

	tmp := t.TempDir()

	// 1. Existing Docker config that does NOT contain credentials for regHost.
	// This simulates standard developer/CI environments where ~/.docker/config.json exists.
	dockerDir := filepath.Join(tmp, "docker")
	if err := os.MkdirAll(dockerDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dockerDir, "config.json"), []byte(`{"auths": {"other.example.com": {"auth": "dGVzdDpwYXNz"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKER_CONFIG", dockerDir)

	// 2. Containers auth file containing credentials for regHost.
	cred := base64.StdEncoding.EncodeToString([]byte("testuser:testpass"))
	authJSON := fmt.Sprintf(`{"auths": {"%s": {"auth": "%s"}}}`, regHost, cred)
	authFilePath := filepath.Join(tmp, "auth.json")
	if err := os.WriteFile(authFilePath, []byte(authJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REGISTRY_AUTH_FILE", authFilePath)

	// 3. Confirm authn.DefaultKeychain reproduces the issue:
	// Because Docker config exists, authn.DefaultKeychain never checks REGISTRY_AUTH_FILE and returns Anonymous.
	defAuth, err := authn.DefaultKeychain.Resolve(target)
	if err != nil {
		t.Fatal(err)
	}
	if defAuth != authn.Anonymous {
		t.Fatalf("expected authn.DefaultKeychain to return Anonymous when Docker config exists, got %v", defAuth)
	}

	imgRef, err := name.ParseReference(fmt.Sprintf("%s/e2e-test-image:latest", regHost), name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	img, err := random.Image(1024, 1)
	if err != nil {
		t.Fatal(err)
	}

	// Remote write fails with 401 Unauthorized under authn.DefaultKeychain
	err = remote.Write(imgRef, img, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err == nil {
		t.Fatal("expected remote.Write with authn.DefaultKeychain to fail with 401 Unauthorized, but it succeeded")
	}

	// 4. Confirm Cosign DefaultContainersKeychain fixes the issue:
	containersAuth, err := options.DefaultContainersKeychain.Resolve(target)
	if err != nil {
		t.Fatal(err)
	}
	if containersAuth == authn.Anonymous {
		t.Fatal("expected DefaultContainersKeychain to resolve credentials from REGISTRY_AUTH_FILE, got Anonymous")
	}

	err = remote.Write(imgRef, img, remote.WithAuthFromKeychain(options.DefaultContainersKeychain))
	if err != nil {
		t.Fatalf("expected remote.Write with DefaultContainersKeychain to succeed, got %v", err)
	}

	// 5. Confirm RegistryOptions client options successfully reads back the image
	ro := &options.RegistryOptions{
		AllowHTTPRegistry: true,
		AllowInsecure:     true,
	}
	opts := ro.GetRegistryClientOpts(context.Background())
	desc, err := remote.Get(imgRef, opts...)
	if err != nil {
		t.Fatalf("expected remote.Get with RegistryOptions to succeed, got %v", err)
	}
	if desc.Digest == (v1.Hash{}) {
		t.Fatal("expected non-empty digest")
	}
}
