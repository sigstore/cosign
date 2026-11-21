package options

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
)

// ContainersKeychain resolves credentials across containers-native auth files
// ($REGISTRY_AUTH_FILE, $XDG_RUNTIME_DIR, $XDG_CONFIG_HOME) and standard Docker config.
type ContainersKeychain struct {
	dockerKeychain authn.Keychain
}

// DefaultContainersKeychain is the default keychain with containers fallback.
var DefaultContainersKeychain authn.Keychain = &ContainersKeychain{
	dockerKeychain: authn.DefaultKeychain,
}

type authConfigFile struct {
	Auths map[string]authEntry `json:"auths"`
}

type authEntry struct {
	Auth     string `json:"auth"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// Resolve implements authn.Keychain. Precedence order:
// 1. $REGISTRY_AUTH_FILE (when set and exists)
// 2. Standard Docker config via authn.DefaultKeychain
// 3. $XDG_RUNTIME_DIR/containers/auth.json
// 4. $XDG_CONFIG_HOME/containers/auth.json or ~/.config/containers/auth.json
func (k *ContainersKeychain) Resolve(target authn.Resource) (authn.Authenticator, error) {
	// 1. Explicit $REGISTRY_AUTH_FILE
	if authFile := os.Getenv("REGISTRY_AUTH_FILE"); authFile != "" {
		if auth, err := resolveFromAuthFile(authFile, target); err == nil && auth != nil {
			return auth, nil
		}
	}

	// 2. Docker config fallback
	if k.dockerKeychain != nil {
		if auth, err := k.dockerKeychain.Resolve(target); err == nil && auth != authn.Anonymous {
			return auth, nil
		}
	}

	// 3. $XDG_RUNTIME_DIR/containers/auth.json
	if runtimeDir := os.Getenv("XDG_RUNTIME_DIR"); runtimeDir != "" {
		p := filepath.Join(runtimeDir, "containers", "auth.json")
		if auth, err := resolveFromAuthFile(p, target); err == nil && auth != nil {
			return auth, nil
		}
	}

	// 4. $XDG_CONFIG_HOME/containers/auth.json (fallback ~/.config/containers/auth.json)
	configDir := os.Getenv("XDG_CONFIG_HOME")
	if configDir == "" {
		if home, err := os.UserHomeDir(); err == nil {
			configDir = filepath.Join(home, ".config")
		}
	}
	if configDir != "" {
		p := filepath.Join(configDir, "containers", "auth.json")
		if auth, err := resolveFromAuthFile(p, target); err == nil && auth != nil {
			return auth, nil
		}
	}

	return authn.Anonymous, nil
}

func resolveFromAuthFile(path string, target authn.Resource) (authn.Authenticator, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var conf authConfigFile
	if err := json.Unmarshal(data, &conf); err != nil {
		return nil, err
	}

	candidates := []string{target.String(), target.RegistryStr()}
	for _, reg := range candidates {
		if entry, ok := conf.Auths[reg]; ok {
			if entry.Auth != "" {
				if decoded, err := base64.StdEncoding.DecodeString(entry.Auth); err == nil {
					parts := strings.SplitN(string(decoded), ":", 2)
					if len(parts) == 2 {
						return &authn.Basic{Username: parts[0], Password: parts[1]}, nil
					}
				}
				return authn.FromConfig(authn.AuthConfig{Auth: entry.Auth}), nil
			}
			if entry.Username != "" && entry.Password != "" {
				return &authn.Basic{Username: entry.Username, Password: entry.Password}, nil
			}
		}
	}

	return nil, nil
}
