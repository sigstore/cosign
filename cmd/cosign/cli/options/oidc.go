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

const DefaultOIDCIssuerURL = "https://oauth2.sigstore.dev/auth"

// OIDCOptions is the wrapper for OIDC related options.
type OIDCOptions struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURI  string
}

var _ Interface = (*OIDCOptions)(nil)

// AddFlags implements Interface
func (o *OIDCOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.Issuer, "oidc-issuer", DefaultOIDCIssuerURL,
		"[EXPERIMENTAL] OIDC provider to be used to issue ID token")

	cmd.Flags().StringVar(&o.ClientID, "oidc-client-id", "sigstore",
		"[EXPERIMENTAL] OIDC client ID for application")

	cmd.Flags().StringVar(&o.ClientSecret, "oidc-client-secret", "",
		"[EXPERIMENTAL] OIDC client secret for application")

	cmd.Flags().StringVar(&o.RedirectURI, "oidc-redirect-uri", "",
		"[EXPERIMENTAL] OIDC redirect URI")
}
