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

package options

import (
	"github.com/spf13/cobra"
)

type SigningConfigCreateOptions struct {
	Fulcio       []string
	Rekor        []string
	OIDCProvider []string
	TSA          []string
	TSAConfig    string
	RekorConfig  string
	Out          string
}

var _ Interface = (*SigningConfigCreateOptions)(nil)

func (o *SigningConfigCreateOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringArrayVar(&o.Fulcio, "fulcio", nil,
		"fulcio service specification, as a comma-separated key-value list.\nRequired keys: url, api-version (integer), start-time, operator. Optional keys: end-time.")
	cmd.Flags().StringArrayVar(&o.Rekor, "rekor", nil,
		"rekor service specification, as a comma-separated key-value list.\nRequired keys: url, api-version (integer), start-time, operator. Optional keys: end-time.")
	cmd.Flags().StringArrayVar(&o.OIDCProvider, "oidc-provider", nil,
		"oidc provider specification, as a comma-separated key-value list.\nRequired keys: url, api-version (integer), start-time, operator. Optional keys: end-time.")
	cmd.Flags().StringArrayVar(&o.TSA, "tsa", nil,
		"timestamping authority specification, as a comma-separated key-value list.\nRequired keys: url, api-version (integer), start-time, operator. Optional keys: end-time.")

	cmd.Flags().StringVar(&o.TSAConfig, "tsa-config", "",
		"timestamping authority configuration. Required if --tsa is provided. One of: ANY, ALL, EXACT:<count>")
	cmd.Flags().StringVar(&o.RekorConfig, "rekor-config", "",
		"rekor configuration. Required if --rekor is provided. One of: ANY, ALL, EXACT:<count>")

	cmd.Flags().StringVar(&o.Out, "out", "", "path to output signing config")
}
