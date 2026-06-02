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

package cli

import (
	"errors"

	"github.com/spf13/cobra"
)

type VerifyOpts struct {
	KeyRef                       string
	BundlePath                   string
	CertIdentity                 string
	CertIdentityIssuer           string
	CertIdentityRegexp           string
	CertIdentityIssuerRegexp     string
	CertGithubWorkflowTrigger    string
	CertGithubWorkflowSha        string
	CertGithubWorkflowName       string
	CertGithubWorkflowRepository string
	CertGithubWorkflowRef        string
	IgnoreSCT                    bool
	Offline                      bool
	IgnoreTlog                   bool
	UseSignedTimestamps          bool
	TrustedRootPath              string
	PredicateType                string
	CheckClaims                  bool
}

func (vo *VerifyOpts) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&vo.KeyRef, "key", "", "path to the public key file")
	_ = cmd.MarkFlagFilename("key", "pub")

	cmd.Flags().StringVar(&vo.BundlePath, "bundle", "", "path to bundle FILE")
	_ = cmd.MarkFlagRequired("bundle")
	_ = cmd.MarkFlagFilename("bundle", "json")

	cmd.Flags().StringVar(&vo.CertIdentity, "certificate-identity", "", "The identity expected in a valid Fulcio certificate. Valid values include email address, DNS names, IP addresses, and URIs. Either --certificate-identity or --certificate-identity-regexp must be set for keyless flows.")
	cmd.Flags().StringVar(&vo.CertIdentityIssuer, "certificate-oidc-issuer", "", "The OIDC issuer expected in a valid Fulcio certificate, e.g. https://token.actions.githubusercontent.com or https://oauth2.sigstore.dev/auth. Either --certificate-oidc-issuer or --certificate-oidc-issuer-regexp must be set for keyless flows.")
	cmd.Flags().StringVar(&vo.CertIdentityRegexp, "certificate-identity-regexp", "", "A regular expression alternative to --certificate-identity. Accepts the Go regular expression syntax described at https://golang.org/s/re2syntax. Either --certificate-identity or --certificate-identity-regexp must be set for keyless flows.")
	cmd.Flags().StringVar(&vo.CertIdentityIssuerRegexp, "certificate-oidc-issuer-regexp", "", "A regular expression alternative to --certificate-oidc-issuer. Accepts the Go regular expression syntax described at https://golang.org/s/re2syntax. Either --certificate-oidc-issuer or --certificate-oidc-issuer-regexp must be set for keyless flows.")

	cmd.Flags().StringVar(&vo.CertGithubWorkflowTrigger, "certificate-github-workflow-trigger", "", "contains the event_name claim from the GitHub OIDC Identity token that contains the name of the event that triggered the workflow run")
	cmd.Flags().StringVar(&vo.CertGithubWorkflowSha, "certificate-github-workflow-sha", "", "contains the sha claim from the GitHub OIDC Identity token that contains the commit SHA that the workflow run was based upon.")
	cmd.Flags().StringVar(&vo.CertGithubWorkflowName, "certificate-github-workflow-name", "", "contains the workflow claim from the GitHub OIDC Identity token that contains the name of the executed workflow.")
	cmd.Flags().StringVar(&vo.CertGithubWorkflowRepository, "certificate-github-workflow-repository", "", "contains the repository claim from the GitHub OIDC Identity token that contains the repository that the workflow run was based upon")
	cmd.Flags().StringVar(&vo.CertGithubWorkflowRef, "certificate-github-workflow-ref", "", "contains the ref claim from the GitHub OIDC Identity token that contains the git ref that the workflow run was based upon.")

	cmd.Flags().BoolVar(&vo.IgnoreSCT, "insecure-ignore-sct", false, "when set, verification will not check that a certificate contains an embedded SCT, a proof of inclusion in a certificate transparency log")
	cmd.Flags().BoolVar(&vo.Offline, "offline", false, "only verify an artifact's inclusion in a transparency log using a provided proof, rather than querying the log. May still include network requests to retrieve service keys from a TUF repository")
	cmd.Flags().BoolVar(&vo.IgnoreTlog, "insecure-ignore-tlog", false, "ignore transparency log verification, to be used when an artifact signature has not been uploaded to the transparency log. Artifacts cannot be publicly verified when not included in a log")
	cmd.Flags().BoolVar(&vo.UseSignedTimestamps, "use-signed-timestamps", false, "verify rfc3161 timestamps")
	cmd.Flags().StringVar(&vo.TrustedRootPath, "trusted-root", "", "Path to a Sigstore TrustedRoot JSON file.")
	_ = cmd.MarkFlagFilename("trusted-root", "json")
}

func (vo *VerifyOpts) Validate() error {
	if vo.BundlePath == "" {
		return errors.New("--bundle is required")
	}

	if vo.KeyRef != "" && (vo.CertIdentity != "" || vo.CertIdentityRegexp != "") {
		return errors.New("cannot specify both --key and --certificate-identity options")
	}

	return nil
}
