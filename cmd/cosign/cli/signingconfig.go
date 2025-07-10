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

package cli

import (
	"context"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/signingconfig"
	"github.com/spf13/cobra"
)

func SigningConfig() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "signing-config",
		Short: "Interact with a Sigstore protobuf signing config",
		Long:  "Tool for interacting with a Sigstore protobuf signing config",
	}

	cmd.AddCommand(signingConfigCreate())

	return cmd
}

func signingConfigCreate() *cobra.Command {
	o := &options.SigningConfigCreateOptions{}

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a Sigstore protobuf signing config",
		Long: `Create a Sigstore protobuf signing config by supplying verification material for Fulcio, Rekor, OIDC, and TSA services.
Each service is specified via a repeatable flag (--fulcio, --rekor, --oidc-provider, --tsa) that takes a comma-separated list of key-value pairs.`,
		Example: `cosign signing-config create \
    --fulcio="url=https://fulcio.sigstore.dev,api-version=1,start-time=2024-01-01T00:00:00Z,end-time=2025-01-01T00:00:00Z,operator=sigstore.dev" \
    --rekor="url=https://rekor.sigstore.dev,api-version=1,start-time=2024-01-01T00:00:00Z,operator=sigstore.dev" \
    --rekor-config="ANY" \
    --oidc-provider="url=https://oauth2.sigstore.dev/auth,api-version=1,start-time=2024-01-01T00:00:00Z,operator=sigstore.dev" \
    --tsa="url=https://timestamp.sigstore.dev/api/v1/timestamp,api-version=1,start-time=2024-01-01T00:00:00Z,operator=sigstore.dev" \
    --tsa-config="EXACT:1" \
    --out signing-config.json`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			scCreateCmd := &signingconfig.CreateCmd{
				FulcioSpecs:       o.Fulcio,
				RekorSpecs:        o.Rekor,
				OIDCProviderSpecs: o.OIDCProvider,
				TSASpecs:          o.TSA,
				TSAConfig:         o.TSAConfig,
				RekorConfig:       o.RekorConfig,
				Out:               o.Out,
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), ro.Timeout)
			defer cancel()

			return scCreateCmd.Exec(ctx)
		},
	}

	o.AddFlags(cmd)
	return cmd
}
