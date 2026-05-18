// Copyright 2025 The Sigstore Authors.
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

package signingconfig

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	prototrustroot "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestCreateCmd(t *testing.T) {
	ctx := context.Background()
	td := t.TempDir()
	outPath := filepath.Join(td, "signingconfig.json")

	startTime := "2024-01-01T00:00:00Z"
	fulcioSpec := fmt.Sprintf("url=https://fulcio.sigstore.example,api-version=1,operator=fulcio-op,start-time=%s", startTime)
	rekorSpec := fmt.Sprintf("url=https://rekor.sigstore.example,api-version=1,operator=rekor-op,start-time=%s", startTime)
	oidcSpec := fmt.Sprintf("url=https://oauth2.sigstore.dev/auth,api-version=1,operator=oidc-op,start-time=%s", startTime)
	tsaSpec := fmt.Sprintf("url=https://tsa.sigstore.example,api-version=1,operator=tsa-op,start-time=%s", startTime)

	signingConfigCreate := CreateCmd{
		FulcioSpecs:       []string{fulcioSpec},
		RekorSpecs:        []string{rekorSpec},
		OIDCProviderSpecs: []string{oidcSpec},
		TSASpecs:          []string{tsaSpec},
		RekorConfig:       "EXACT:1",
		TSAConfig:         "ANY",
		Out:               outPath,
	}

	err := signingConfigCreate.Exec(ctx)
	checkErr(t, err)

	scBytes, err := os.ReadFile(outPath)
	checkErr(t, err)

	var sc prototrustroot.SigningConfig
	err = protojson.Unmarshal(scBytes, &sc)
	checkErr(t, err)

	if sc.GetMediaType() != root.SigningConfigMediaType02 {
		t.Fatalf("unexpected media type: got %s, want %s", sc.GetMediaType(), root.SigningConfigMediaType02)
	}

	if len(sc.GetCaUrls()) != 1 {
		t.Fatal("unexpected number of fulcio services")
	}
	if sc.GetCaUrls()[0].GetOperator() != "fulcio-op" {
		t.Fatalf("unexpected fulcio operator: %s", sc.GetCaUrls()[0].GetOperator())
	}
	if sc.GetCaUrls()[0].GetUrl() != "https://fulcio.sigstore.example" {
		t.Fatalf("unexpected fulcio url: %s", sc.GetCaUrls()[0].GetUrl())
	}
	if sc.GetCaUrls()[0].GetMajorApiVersion() != 1 {
		t.Fatalf("unexpected fulcio api version: %d", sc.GetCaUrls()[0].GetMajorApiVersion())
	}

	if len(sc.GetRekorTlogUrls()) != 1 {
		t.Fatal("unexpected number of rekor services")
	}
	if sc.GetRekorTlogUrls()[0].GetOperator() != "rekor-op" {
		t.Fatalf("unexpected rekor operator: %s", sc.GetRekorTlogUrls()[0].GetOperator())
	}
	if sc.GetRekorTlogUrls()[0].GetMajorApiVersion() != 1 {
		t.Fatalf("unexpected rekor api version: %d", sc.GetRekorTlogUrls()[0].GetMajorApiVersion())
	}

	if len(sc.GetOidcUrls()) != 1 {
		t.Fatal("unexpected number of oidc providers")
	}
	if sc.GetOidcUrls()[0].GetOperator() != "oidc-op" {
		t.Fatalf("unexpected oidc provider operator: %s", sc.GetOidcUrls()[0].GetOperator())
	}
	if sc.GetOidcUrls()[0].GetMajorApiVersion() != 1 {
		t.Fatalf("unexpected oidc provider api version: %d", sc.GetOidcUrls()[0].GetMajorApiVersion())
	}

	if len(sc.GetTsaUrls()) != 1 {
		t.Fatal("unexpected number of tsa services")
	}
	if sc.GetTsaUrls()[0].GetOperator() != "tsa-op" {
		t.Fatalf("unexpected tsa operator: %s", sc.GetTsaUrls()[0].GetOperator())
	}
	if sc.GetTsaUrls()[0].GetMajorApiVersion() != 1 {
		t.Fatalf("unexpected tsa api version: %d", sc.GetTsaUrls()[0].GetMajorApiVersion())
	}

	// Check start time is set
	expectedStart, _ := time.Parse(time.RFC3339, startTime)
	if !sc.GetCaUrls()[0].GetValidFor().GetStart().AsTime().Equal(expectedStart) {
		t.Fatal("unexpected fulcio start time")
	}
	if !sc.GetRekorTlogUrls()[0].GetValidFor().GetStart().AsTime().Equal(expectedStart) {
		t.Fatal("unexpected rekor start time")
	}
	if !sc.GetOidcUrls()[0].GetValidFor().GetStart().AsTime().Equal(expectedStart) {
		t.Fatal("unexpected oidc provider start time")
	}
	if !sc.GetTsaUrls()[0].GetValidFor().GetStart().AsTime().Equal(expectedStart) {
		t.Fatal("unexpected tsa start time")
	}

	if sc.GetRekorTlogConfig() == nil {
		t.Fatal("expected rekor config to be set")
	}
	if sc.GetRekorTlogConfig().GetSelector() != prototrustroot.ServiceSelector_EXACT || sc.GetRekorTlogConfig().GetCount() != 1 {
		t.Fatalf("unexpected rekor config: %+v", sc.GetRekorTlogConfig())
	}

	if sc.GetTsaConfig() == nil {
		t.Fatal("expected tsa config to be set")
	}
	if sc.GetTsaConfig().GetSelector() != prototrustroot.ServiceSelector_ANY {
		t.Fatalf("unexpected tsa config: %+v", sc.GetTsaConfig())
	}

	// Test with end time
	rekorSpecWithEndTime := fmt.Sprintf("%s,end-time=2025-01-01T00:00:00Z", rekorSpec)
	signingConfigCreate.RekorSpecs = []string{rekorSpecWithEndTime}
	err = signingConfigCreate.Exec(ctx)
	checkErr(t, err)
	scBytes, err = os.ReadFile(outPath)
	checkErr(t, err)
	err = protojson.Unmarshal(scBytes, &sc)
	checkErr(t, err)

	if sc.GetRekorTlogUrls()[0].GetValidFor().GetEnd().AsTime().IsZero() {
		t.Fatal("expected end time to be set")
	}
	expectedEnd, _ := time.Parse(time.RFC3339, "2025-01-01T00:00:00Z")
	if !sc.GetRekorTlogUrls()[0].GetValidFor().GetEnd().AsTime().Equal(expectedEnd) {
		t.Fatal("unexpected end time")
	}

	// Test missing required fields
	for _, key := range []string{"url", "api-version", "start-time", "operator"} {
		t.Run(fmt.Sprintf("missing %s", key), func(t *testing.T) {
			// Create a spec with one key missing
			specMap := map[string]string{
				"url":         "https://rekor.sigstore.example",
				"api-version": "1",
				"start-time":  startTime,
				"operator":    "rekor-op",
			}
			delete(specMap, key)

			pairs := make([]string, 0, len(specMap))
			for k, v := range specMap {
				pairs = append(pairs, fmt.Sprintf("%s=%s", k, v))
			}
			invalidSpec := strings.Join(pairs, ",")

			cmdCopy := signingConfigCreate
			cmdCopy.RekorSpecs = []string{invalidSpec}
			err := cmdCopy.Exec(ctx)
			if err == nil {
				t.Fatalf("expected error for missing required field '%s', but got none", key)
			}
		})
	}

	// Test missing rekor-config
	signingConfigCreate.RekorSpecs = []string{rekorSpec}
	signingConfigCreate.RekorConfig = ""
	err = signingConfigCreate.Exec(ctx)
	if err == nil {
		t.Fatal("expected error for missing rekor-config, but got none")
	}
	signingConfigCreate.RekorConfig = "EXACT:1" // reset

	// Test missing tsa-config
	signingConfigCreate.TSASpecs = []string{tsaSpec}
	signingConfigCreate.TSAConfig = ""
	err = signingConfigCreate.Exec(ctx)
	if err == nil {
		t.Fatal("expected error for missing tsa-config, but got none")
	}
	signingConfigCreate.TSAConfig = "ANY" // reset

	// Test RekorV2
	tufRepo := t.TempDir()
	err = newTUF(tufRepo, map[string][]byte{
		"signing_config_rekor_v2.v0.2.json": []byte(`{
			"mediaType": "application/vnd.dev.sigstore.signingconfig.v0.2+json",
			"rekorTlogConfig": {"selector": "EXACT", "count": 1},
			"tsaConfig": {"selector": "ANY"}
		}`),
	})
	checkErr(t, err)
	tufServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.FileServer(http.Dir(tufRepo)).ServeHTTP(w, r)
	}))
	defer tufServer.Close()
	t.Setenv("TUF_MIRROR", tufServer.URL)
	t.Setenv("TUF_ROOT_JSON", filepath.Join(tufRepo, "1.root.json"))
	t.Setenv("TUF_ROOT", t.TempDir())
	signingConfigCreateRekorV2 := CreateCmd{
		WithDefaultServices: true,
		RekorV2:             true,
		Out:                 filepath.Join(td, "signingconfig_rekor_v2.json"),
	}
	err = signingConfigCreateRekorV2.Exec(ctx)
	checkErr(t, err)
}

func checkErr(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

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
