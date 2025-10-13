// Copyright 2025 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package initialize

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func newKey() (*metadata.Key, signature.Signer, error) {
	pub, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, err
	}
	public, err := metadata.KeyFromPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}
	signer, err := signature.LoadSigner(private, crypto.Hash(0))
	if err != nil {
		return nil, nil, err
	}
	return public, signer, nil
}

func newTUF(td string, targetList map[string][]byte) error {
	expiration := time.Now().AddDate(0, 0, 1).UTC()
	targets := metadata.Targets(expiration)
	targetsDir := filepath.Join(td, "targets")
	err := os.Mkdir(targetsDir, 0700)
	if err != nil {
		return err
	}
	for name, content := range targetList {
		targetPath := filepath.Join(targetsDir, name)
		err := os.WriteFile(targetPath, content, 0600)
		if err != nil {
			return err
		}
		targetFileInfo, err := metadata.TargetFile().FromFile(targetPath, "sha256")
		if err != nil {
			return err
		}
		targets.Signed.Targets[name] = targetFileInfo
	}
	snapshot := metadata.Snapshot(expiration)
	timestamp := metadata.Timestamp(expiration)
	root := metadata.Root(expiration)
	root.Signed.ConsistentSnapshot = false
	public, signer, err := newKey()
	if err != nil {
		return err
	}
	for _, name := range []string{"targets", "snapshot", "timestamp", "root"} {
		err := root.Signed.AddKey(public, name)
		if err != nil {
			return err
		}
		switch name {
		case "targets":
			_, err = targets.Sign(signer)
		case "snapshot":
			_, err = snapshot.Sign(signer)
		case "timestamp":
			_, err = timestamp.Sign(signer)
		case "root":
			_, err = root.Sign(signer)
		}
		if err != nil {
			return err
		}
	}
	err = targets.ToFile(filepath.Join(td, "targets.json"), false)
	if err != nil {
		return err
	}
	err = snapshot.ToFile(filepath.Join(td, "snapshot.json"), false)
	if err != nil {
		return err
	}
	err = timestamp.ToFile(filepath.Join(td, "timestamp.json"), false)
	if err != nil {
		return err
	}
	err = root.ToFile(filepath.Join(td, "1.root.json"), false)
	if err != nil {
		return err
	}
	err = root.VerifyDelegate("root", root)
	if err != nil {
		return err
	}
	err = root.VerifyDelegate("targets", targets)
	if err != nil {
		return err
	}
	err = root.VerifyDelegate("snapshot", snapshot)
	if err != nil {
		return err
	}
	err = root.VerifyDelegate("timestamp", timestamp)
	return err
}

func captureOutput(f func() error) (string, string, error) {
	stdout := os.Stdout
	stderr := os.Stderr
	rout, wout, _ := os.Pipe()
	os.Stdout = wout
	rerr, werr, _ := os.Pipe()
	os.Stderr = werr
	err := f()
	os.Stdout = stdout
	os.Stderr = stderr
	wout.Close()
	werr.Close()
	out, _ := io.ReadAll(rout)
	errMsg, _ := io.ReadAll(rerr)
	return string(out), string(errMsg), err
}

func TestDoInitialize(t *testing.T) {
	tests := []struct {
		name       string
		targets    map[string][]byte
		root       string
		wantStdOut string
		wantStdErr string
		wantErr    bool
		wantFiles  []string
		expectV2   bool
	}{
		{
			name: "tuf v2 with trusted root and signing config",
			targets: map[string][]byte{
				"trusted_root.json":        []byte(`{"mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1"}`),
				"signing_config.v0.2.json": []byte(`{"mediaType": "application/vnd.dev.sigstore.signingconfig.v0.2+json"}`),
			},
			root:       "1.root.json",
			wantStdOut: "",
			wantStdErr: "",
			wantErr:    false,
			wantFiles:  []string{filepath.Join("targets", "trusted_root.json"), filepath.Join("targets", "signing_config.v0.2.json")},
			expectV2:   true,
		},
		{
			name:       "tuf v1",
			targets:    map[string][]byte{"ctfe.pub": []byte(`-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----`)},
			root:       "1.root.json",
			wantStdOut: "ctfe.pub",
			wantStdErr: "WARNING: Could not fetch trusted_root.json from the TUF mirror (encountered error: failed to get target from TUF client getting info for target \"trusted_root.json\": target trusted_root.json not found), falling back to individual targets. It is recommended to update your TUF metadata repository to include trusted_root.json.",
			wantErr:    false,
			wantFiles:  []string{filepath.Join("targets", "ctfe.pub")},
			expectV2:   false,
		},
		{
			name:    "invalid root - should not try to use embedded",
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tufRepo := t.TempDir()
			err := newTUF(tufRepo, test.targets)
			if err != nil {
				t.Fatal(err)
			}
			tufServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.FileServer(http.Dir(tufRepo)).ServeHTTP(w, r)
			}))
			rootJSONPath := filepath.Join(tufRepo, test.root)
			tufCache := t.TempDir()
			t.Setenv("TUF_ROOT", tufCache)
			gotStdOut, gotStdErr, gotErr := captureOutput(func() error {
				return DoInitialize(context.Background(), rootJSONPath, tufServer.URL)
			})
			if test.wantErr {
				assert.Error(t, gotErr)
				return
			}
			assert.NoError(t, gotErr)
			if test.wantStdOut == "" {
				assert.Empty(t, gotStdOut)
			} else {
				assert.Contains(t, gotStdOut, test.wantStdOut)
			}
			if test.wantStdErr == "" {
				assert.Empty(t, gotStdErr)
			} else {
				assert.Contains(t, gotStdErr, test.wantStdErr)
			}
			var mirrorDir string
			if test.expectV2 {
				mirrorDir = tufServer.URL
				mirrorDir, _ = strings.CutPrefix(mirrorDir, "http://")
				mirrorDir = strings.ReplaceAll(mirrorDir, "/", "-")
				mirrorDir = strings.ReplaceAll(mirrorDir, ":", "-")
			}
			for _, f := range test.wantFiles {
				assert.FileExists(t, filepath.Join(tufCache, mirrorDir, f))
			}
			assert.FileExists(t, filepath.Join(tufCache, "remote.json"))
		})
	}
}
