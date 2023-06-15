//
// Copyright 2022 The Sigstore Authors.
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

import "github.com/spf13/cobra"

// DownloadOptions is the struct for control
type SBOMDownloadOptions struct {
	Platform string // Platform to download sboms
}

type AttestationDownloadOptions struct {
	PredicateType string // Predicate type of attestation to retrieve
	Platform      string // Platform to download attestations
}

var _ Interface = (*SBOMDownloadOptions)(nil)

var _ Interface = (*AttestationDownloadOptions)(nil)

// AddFlags implements Interface
func (o *SBOMDownloadOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.Platform, "platform", "",
		"download SBOM for a specific platform image")
}

// AddFlags implements Interface
func (o *AttestationDownloadOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.PredicateType, "predicate-type", "",
		"download attestation with matching predicateType")
	cmd.Flags().StringVar(&o.Platform, "platform", "",
		"download attestation for a specific platform image")
}
