package options

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
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
