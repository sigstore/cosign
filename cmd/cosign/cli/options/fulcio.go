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
	fulcioclient "github.com/sigstore/fulcio/pkg/client"
	"github.com/spf13/cobra"
)

// FulcioOptions is the wrapper for Fulcio related options.
type FulcioOptions struct {
	URL           string
	IdentityToken string
}

// AddFulcioOptions adds the Fulcio related options to cmd.
func AddFulcioOptions(cmd *cobra.Command, o *FulcioOptions) {
	cmd.Flags().StringVar(&o.URL, "fulcio-url", fulcioclient.SigstorePublicServerURL,
		"[EXPERIMENTAL] address of sigstore PKI server")

	cmd.Flags().StringVar(&o.IdentityToken, "identity-token", "",
		"[EXPERIMENTAL] identity token to use for certificate from fulcio")
}
