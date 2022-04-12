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

import (
	"github.com/spf13/cobra"
)

// CertVerifyOptions is the wrapper for certificate verification.
type CertVerifyOptions struct {
	Cert           string
	CertEmail      string
	CertOidcIssuer string
	CertChain      string
	EnforceSCT     bool
}

var _ Interface = (*RekorOptions)(nil)

// AddFlags implements Interface
func (o *CertVerifyOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.Cert, "cert", "",
		"path to the public certificate")

	cmd.Flags().StringVar(&o.CertEmail, "cert-email", "",
		"the email expected in a valid Fulcio certificate")

	cmd.Flags().StringVar(&o.CertOidcIssuer, "cert-oidc-issuer", "",
		"the OIDC issuer expected in a valid Fulcio certificate, e.g. https://token.actions.githubusercontent.com or https://oauth2.sigstore.dev/auth")

	cmd.Flags().StringVar(&o.CertChain, "cert-chain", "",
		"path to a list of CA certificates in PEM format which will be needed "+
			"when building the certificate chain for the signing certificate. "+
			"Must start with the parent intermediate CA certificate of the "+
			"signing certificate and end with the root certificate")

	cmd.Flags().BoolVar(&o.EnforceSCT, "enforce-sct", false,
		"whether to enforce that a certificate contain an embedded SCT, a proof of "+
			"inclusion in a certificate transparency log")
}
