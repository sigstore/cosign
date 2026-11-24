package options

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
)

type mockKeychain struct {
	auths map[string]authn.Authenticator
}

func (m *mockKeychain) Resolve(target authn.Resource) (authn.Authenticator, error) {
	if a, ok := m.auths[target.RegistryStr()]; ok {
		return a, nil
	}
	return authn.Anonymous, nil
}

func createTestAuthFile(t *testing.T, dir, reg, user, pass string) string {
	t.Helper()
	p := filepath.Join(dir, "auth.json")
	cred := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", user, pass)))
	content := fmt.Sprintf(`{"auths": {"%s": {"auth": "%s"}}}`, reg, cred)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestContainersKeychain_Precedence(t *testing.T) {
	tmp := t.TempDir()
	reg := "registry.example.com"
	target, err := name.NewRegistry(reg)
	if err != nil {
		t.Fatal(err)
	}

	// 1. REGISTRY_AUTH_FILE takes top precedence
	authFilePath := createTestAuthFile(t, tmp, reg, "envuser", "envpass")
	t.Setenv("REGISTRY_AUTH_FILE", authFilePath)

	dockerMock := &mockKeychain{
		auths: map[string]authn.Authenticator{
			reg: &authn.Basic{Username: "dockeruser", Password: "dockerpass"},
		},
	}
	kc := &ContainersKeychain{dockerKeychain: dockerMock}

	authenticator, err := kc.Resolve(target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cfg, err := authenticator.Authorization()
	if err != nil {
		t.Fatalf("failed authorization: %v", err)
	}
	if cfg.Username != "envuser" {
		t.Errorf("expected envuser, got %s", cfg.Username)
	}

	// 2. Unset REGISTRY_AUTH_FILE -> Docker mock wins
	t.Setenv("REGISTRY_AUTH_FILE", "")
	authenticator, err = kc.Resolve(target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cfg, _ = authenticator.Authorization()
	if cfg.Username != "dockeruser" {
		t.Errorf("expected dockeruser, got %s", cfg.Username)
	}

	// 3. Docker lacks registry -> Falls back to containers runtime path
	kc.dockerKeychain = &mockKeychain{auths: map[string]authn.Authenticator{}}
	runtimeDir := filepath.Join(tmp, "runtime")
	if err := os.MkdirAll(filepath.Join(runtimeDir, "containers"), 0o700); err != nil {
		t.Fatal(err)
	}
	createTestAuthFile(t, filepath.Join(runtimeDir, "containers"), reg, "podmanuser", "podmanpass")
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)

	authenticator, err = kc.Resolve(target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cfg, _ = authenticator.Authorization()
	if cfg.Username != "podmanuser" {
		t.Errorf("expected podmanuser, got %s", cfg.Username)
	}

	// 4. Runtime lacks registry -> Falls back to XDG_CONFIG_HOME
	configDir := filepath.Join(tmp, "config")
	if err := os.MkdirAll(filepath.Join(configDir, "containers"), 0o700); err != nil {
		t.Fatal(err)
	}
	createTestAuthFile(t, filepath.Join(configDir, "containers"), reg, "configuser", "configpass")
	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv("XDG_CONFIG_HOME", configDir)

	authenticator, err = kc.Resolve(target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cfg, _ = authenticator.Authorization()
	if cfg.Username != "configuser" {
		t.Errorf("expected configuser, got %s", cfg.Username)
	}

	// 5. No matches -> Anonymous
	t.Setenv("XDG_CONFIG_HOME", "")
	authenticator, err = kc.Resolve(target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if authenticator != authn.Anonymous {
		t.Errorf("expected authn.Anonymous, got %v", authenticator)
	}
}

// TestContainersKeychain_LiveRegistryAuth verifies end-to-end registry operations
// against an auth-enforcing registry, demonstrating that authn.DefaultKeychain
// fails when a Docker config exists without the registry, and DefaultContainersKeychain
// succeeds by reading containers auth files.
func TestContainersKeychain_LiveRegistryAuth(t *testing.T) {
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

	// 1. Set up Docker config that exists but does NOT contain auth for regHost
	dockerDir := filepath.Join(tmp, "docker")
	if err := os.MkdirAll(dockerDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dockerDir, "config.json"), []byte(`{"auths": {"other.example.com": {"auth": "dGVzdDpwYXNz"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKER_CONFIG", dockerDir)

	// 2. Set up REGISTRY_AUTH_FILE that DOES contain auth for regHost
	authFilePath := createTestAuthFile(t, tmp, regHost, "testuser", "testpass")
	t.Setenv("REGISTRY_AUTH_FILE", authFilePath)

	// 3. Verify authn.DefaultKeychain failure:
	// Because foundDockerConfig == true, go-containerregistry never inspects REGISTRY_AUTH_FILE
	// and returns authn.Anonymous.
	defAuth, err := authn.DefaultKeychain.Resolve(target)
	if err != nil {
		t.Fatal(err)
	}
	if defAuth != authn.Anonymous {
		t.Fatalf("expected authn.DefaultKeychain to return Anonymous when Docker config exists, got %v", defAuth)
	}

	imgRef, err := name.ParseReference(fmt.Sprintf("%s/test-image:latest", regHost), name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	img, err := random.Image(1024, 1)
	if err != nil {
		t.Fatal(err)
	}

	// remote.Write with authn.DefaultKeychain fails with 401 Unauthorized
	err = remote.Write(imgRef, img, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err == nil {
		t.Fatal("expected remote.Write with authn.DefaultKeychain to fail with 401 Unauthorized, but it succeeded")
	}

	// 4. Verify DefaultContainersKeychain resolution and successful write:
	containersAuth, err := DefaultContainersKeychain.Resolve(target)
	if err != nil {
		t.Fatal(err)
	}
	if containersAuth == authn.Anonymous {
		t.Fatal("expected DefaultContainersKeychain to resolve credentials from REGISTRY_AUTH_FILE, got Anonymous")
	}

	err = remote.Write(imgRef, img, remote.WithAuthFromKeychain(DefaultContainersKeychain))
	if err != nil {
		t.Fatalf("expected remote.Write with DefaultContainersKeychain to succeed, got %v", err)
	}

	// 5. Verify RegistryOptions.GetRegistryClientOpts works with DefaultContainersKeychain
	ro := &RegistryOptions{}
	opts := ro.GetRegistryClientOpts(context.Background())
	desc, err := remote.Get(imgRef, opts...)
	if err != nil {
		t.Fatalf("expected remote.Get with RegistryOptions to succeed, got %v", err)
	}
	if desc.Digest == (v1.Hash{}) {
		t.Fatal("expected non-empty digest")
	}

	// 6. Verify fallback to XDG_CONFIG_HOME when REGISTRY_AUTH_FILE is unset
	t.Setenv("REGISTRY_AUTH_FILE", "")
	configDir := filepath.Join(tmp, "config")
	if err := os.MkdirAll(filepath.Join(configDir, "containers"), 0o700); err != nil {
		t.Fatal(err)
	}
	createTestAuthFile(t, filepath.Join(configDir, "containers"), regHost, "testuser", "testpass")
	t.Setenv("XDG_CONFIG_HOME", configDir)

	containersAuth2, err := DefaultContainersKeychain.Resolve(target)
	if err != nil {
		t.Fatal(err)
	}
	if containersAuth2 == authn.Anonymous {
		t.Fatal("expected DefaultContainersKeychain to fall back to XDG_CONFIG_HOME, got Anonymous")
	}

	desc2, err := remote.Get(imgRef, ro.GetRegistryClientOpts(context.Background())...)
	if err != nil {
		t.Fatalf("expected remote.Get with XDG_CONFIG_HOME fallback to succeed, got %v", err)
	}
	if desc2.Digest == (v1.Hash{}) {
		t.Fatal("expected non-empty digest")
	}
}
