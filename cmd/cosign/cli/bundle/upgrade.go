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

package bundle

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	rekor "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/tle"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/sigstore/cosign/v3/internal/ui"
)

type UpgradeCmd struct {
	In       string
	Out      string
	InPlace  string
	RekorURL string
}

func (c *UpgradeCmd) Exec(ctx context.Context) error {
	inputPath := c.In
	if c.InPlace != "" {
		inputPath = c.InPlace
	}

	data, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("reading input file: %w", err)
	}

	if err := detectFormat(data); err != nil {
		return fmt.Errorf("detecting bundle format: %w", err)
	}

	rekorClient, err := rekor.GetRekorClient(c.RekorURL)
	if err != nil {
		return fmt.Errorf("creating rekor client: %w", err)
	}

	upgradedBundle, err := upgradeBundle(ctx, data, rekorClient)
	if err != nil {
		return fmt.Errorf("upgrading bundle: %w", err)
	}

	outputPath := c.Out
	if c.InPlace != "" {
		outputPath = c.InPlace
	}

	err = os.WriteFile(outputPath, upgradedBundle, 0600)
	if err != nil {
		return fmt.Errorf("writing upgraded bundle: %w", err)
	}

	ui.Infof(ctx, "Successfully upgraded bundle written to %s", outputPath)
	return nil
}

func detectFormat(data []byte) error {
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("unmarshaling JSON for detection: %w", err)
	}

	if _, hasMediaType := m["mediaType"]; hasMediaType {
		return nil
	}

	if _, hasBase64Signature := m["base64Signature"]; hasBase64Signature {
		return fmt.Errorf("cannot upgrade legacy bundles; use `cosign bundle create` to create a new bundle from your legacy bundle and artifact")
	}

	return fmt.Errorf("unrecognized bundle format")
}

func upgradeBundle(ctx context.Context, data []byte, rekorClient *client.Rekor) ([]byte, error) {
	var bundle protobundle.Bundle
	if err := protojson.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("unmarshaling bundle: %w", err)
	}

	if bundle.VerificationMaterial == nil {
		return nil, fmt.Errorf("bundle is missing verification material")
	}
	if bundle.VerificationMaterial.Content == nil {
		return nil, fmt.Errorf("bundle verification material is missing content (public key or certificate)")
	}

	switch bundle.MediaType {
	case "application/vnd.dev.sigstore.bundle.v0.3+json", "application/vnd.dev.sigstore.bundle+json;version=0.3":
		ui.Infof(ctx, "Bundle is already at v0.3, no upgrade needed.")
		return data, nil
	case "application/vnd.dev.sigstore.bundle+json;version=0.1":
		ui.Infof(ctx, "Upgrading from v0.1 to v0.3...")
	case "application/vnd.dev.sigstore.bundle+json;version=0.2":
		ui.Infof(ctx, "Upgrading from v0.2 to v0.3...")
	default:
		return nil, fmt.Errorf("unsupported bundle version: %s", bundle.MediaType)
	}

	if chainContent, ok := bundle.VerificationMaterial.Content.(*protobundle.VerificationMaterial_X509CertificateChain); ok {
		certChain := chainContent.X509CertificateChain.Certificates
		if len(certChain) > 0 {
			bundle.VerificationMaterial.Content = &protobundle.VerificationMaterial_Certificate{
				Certificate: certChain[0],
			}
		}
	}

	for i, entry := range bundle.VerificationMaterial.TlogEntries {
		if entry.InclusionPromise != nil && entry.InclusionProof == nil {
			ui.Infof(ctx, "Fetching missing inclusion proof from Rekor for log index %d...", entry.LogIndex)

			params := entries.NewGetLogEntryByIndexParamsWithContext(ctx)
			params.SetLogIndex(entry.LogIndex)

			resp, err := rekorClient.Entries.GetLogEntryByIndex(params)
			if err != nil {
				return nil, fmt.Errorf("fetching log entry by index: %w", err)
			}

			if len(resp.Payload) != 1 {
				return nil, fmt.Errorf("expected exactly 1 entry from Rekor for index %d, got %d", entry.LogIndex, len(resp.Payload))
			}

			for _, e := range resp.Payload {
				protoEntry, err := tle.GenerateTransparencyLogEntry(e)
				if err != nil {
					return nil, fmt.Errorf("generating proto entry: %w", err)
				}
				bundle.VerificationMaterial.TlogEntries[i] = protoEntry
			}
		}
	}

	bundle.MediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"

	out, err := protojson.Marshal(&bundle)
	if err != nil {
		return nil, fmt.Errorf("marshaling bundle: %w", err)
	}

	return out, nil
}
