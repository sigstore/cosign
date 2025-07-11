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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	prototrustroot "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
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

			var pairs []string
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
}

func checkErr(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}
