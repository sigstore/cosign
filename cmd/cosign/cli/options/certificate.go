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
	Cert                         string
	CertEmail                    string
	CertIdentity                 string
	CertOidcIssuer               string
	CertGithubWorkflowTrigger    string
	CertGithubWorkflowSha        string
	CertGithubWorkflowName       string
	CertGithubWorkflowRepository string
	CertGithubWorkflowRef        string
	CertChain                    string
	EnforceSCT                   bool
}

var _ Interface = (*RekorOptions)(nil)

// AddFlags implements Interface
func (o *CertVerifyOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.Cert, "certificate", "",
		"path to the public certificate. The certificate will be verified against the Fulcio roots if the --certificate-chain option is not passed.")
	_ = cmd.Flags().SetAnnotation("certificate", cobra.BashCompFilenameExt, []string{"cert"})

	cmd.Flags().StringVar(&o.CertEmail, "certificate-email", "",
		"the email expected in a valid Fulcio certificate")

	cmd.Flags().StringVar(&o.CertIdentity, "certificate-identity", "",
		"the identity expected in a valid Fulcio certificate. Valid values include email address, DNS names, IP addresses, and URIs.")

	cmd.Flags().StringVar(&o.CertOidcIssuer, "certificate-oidc-issuer", "",
		"the OIDC issuer expected in a valid Fulcio certificate, e.g. https://token.actions.githubusercontent.com or https://oauth2.sigstore.dev/auth")

	// -- Cert extensions begin --
	// Source: https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md
	cmd.Flags().StringVar(&o.CertGithubWorkflowTrigger, "certificate-github-workflow-trigger", "",
		"contains the event_name claim from the GitHub OIDC Identity token that contains the name of the event that triggered the workflow run")

	cmd.Flags().StringVar(&o.CertGithubWorkflowSha, "certificate-github-workflow-sha", "",
		"contains the sha claim from the GitHub OIDC Identity token that contains the commit SHA that the workflow run was based upon.")

	cmd.Flags().StringVar(&o.CertGithubWorkflowName, "certificate-github-workflow-name", "",
		"contains the workflow claim from the GitHub OIDC Identity token that contains the name of the executed workflow.")

	cmd.Flags().StringVar(&o.CertGithubWorkflowRepository, "certificate-github-workflow-repository", "",
		"contains the repository claim from the GitHub OIDC Identity token that contains the repository that the workflow run was based upon")

	cmd.Flags().StringVar(&o.CertGithubWorkflowRef, "certificate-github-workflow-ref", "",
		"contains the ref claim from the GitHub OIDC Identity token that contains the git ref that the workflow run was based upon.")
	// -- Cert extensions end --
	cmd.Flags().StringVar(&o.CertChain, "certificate-chain", "",
		"path to a list of CA certificates in PEM format which will be needed "+
			"when building the certificate chain for the signing certificate. "+
			"Must start with the parent intermediate CA certificate of the "+
			"signing certificate and end with the root certificate")
	_ = cmd.Flags().SetAnnotation("certificate-chain", cobra.BashCompFilenameExt, []string{"cert"})

	cmd.Flags().BoolVar(&o.EnforceSCT, "enforce-sct", false,
		"whether to enforce that a certificate contain an embedded SCT, a proof of "+
			"inclusion in a certificate transparency log")
}
