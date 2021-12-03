//
// Copyright 2021 The Sigstore Authors.
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

// FulcioOptions is the wrapper for Fulcio related options.
type FulcioOptions struct {
	URL                      string
	IdentityToken            string
	InsecureSkipFulcioVerify bool
}

var _ Interface = (*FulcioOptions)(nil)

// AddFlags implements Interface
func (o *FulcioOptions) AddFlags(cmd *cobra.Command) {
	// TODO: change this back to https://fulcio.sigstore.dev after the v1 migration is complete.
	cmd.Flags().StringVar(&o.URL, "fulcio-url", "https://v1.fulcio.sigstore.dev",
		"[EXPERIMENTAL] address of sigstore PKI server")

	cmd.Flags().StringVar(&o.IdentityToken, "identity-token", "",
		"[EXPERIMENTAL] identity token to use for certificate from fulcio")

	cmd.Flags().BoolVar(&o.InsecureSkipFulcioVerify, "insecure-skip-verify", false,
		"[EXPERIMENTAL] skip verifying fulcio published to the SCT (this should only be used for testing).")
}
