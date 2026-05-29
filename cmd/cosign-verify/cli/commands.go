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
	"context"
	"errors"
	"time"

	"github.com/spf13/cobra"
	tufv1 "github.com/sigstore/sigstore/pkg/tuf"
)

func New() *cobra.Command {
	var rootCmd = &cobra.Command{
		Use:               "cosign-verify",
		Short:             "cosign-verify is a minimal verification utility for Sigstore",
		DisableAutoGenTag: true,
	}
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	rootCmd.AddCommand(
		Initialize(),
		Verify(),
		VerifyAttestation(),
	)

	return rootCmd
}

func Initialize() *cobra.Command {
	var mirror string
	var rootPath string
	var rootChecksum string
	var staging bool

	cmd := &cobra.Command{
		Use:   "initialize",
		Short: "Initialize TUF roots of trust",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			switch {
			case staging:
				return doInitializeStaging(ctx)
			case rootChecksum != "":
				return doInitializeWithRootChecksum(ctx, rootPath, mirror, rootChecksum)
			default:
				return doInitialize(ctx, rootPath, mirror)
			}
		},
	}

	cmd.Flags().StringVar(&mirror, "mirror", tufv1.DefaultRemoteRoot, "GCS bucket to a SigStore TUF repository, or HTTP(S) base URL, or file:/// for local filestore remote (air-gap)")
	cmd.Flags().StringVar(&rootPath, "root", "", "path to trusted initial root. defaults to embedded root")
	cmd.Flags().StringVar(&rootChecksum, "root-checksum", "", "checksum of the initial root, required if root is downloaded via http(s). expects sha256 by default, can be changed to sha512 by providing sha512:<checksum>")
	cmd.Flags().BoolVar(&staging, "staging", false, "use the staging TUF repository")

	return cmd
}

func Verify() *cobra.Command {
	var vo VerifyOpts
	var timeout time.Duration

	cmd := &cobra.Command{
		Use:   "verify <payload-file>",
		Short: "Verify a plain payload blob against a standardized Sigstore bundle",
		Long: `Verify the supplied payload blob against a standardized Sigstore verification bundle 
using either a local public key or certificate identities loaded from the bundle.`,
		Example: `  # Verify a payload using a local public key
  cosign-verify verify --bundle payload.bundle.json --key cosign.pub payload.txt

  # Verify a payload keylessly using an OIDC identity subject and issuer
  cosign-verify verify --bundle payload.bundle.json \
    --certificate-identity "user@example.com" \
    --certificate-oidc-issuer "https://accounts.google.com" \
    payload.txt`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			payloadPath := args[0]

			if vo.BundlePath == "" {
				return errors.New("--bundle is required")
			}

			if vo.KeyRef != "" && (vo.CertIdentity != "" || vo.CertIdentityRegexp != "") {
				return errors.New("cannot specify both --key and --certificate-identity options")
			}

			ctx := cmd.Context()
			ctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			return verifyBundle(ctx, vo, payloadPath, false)
		},
	}

	addCommonVerifyFlags(cmd, &vo)
	cmd.Flags().DurationVarP(&timeout, "timeout", "t", 3*time.Minute, "timeout for commands")

	return cmd
}

func VerifyAttestation() *cobra.Command {
	var vo VerifyOpts
	var timeout time.Duration

	cmd := &cobra.Command{
		Use:   "verify-attestation [payload-file]",
		Short: "Verify a signed in-toto statement and output its payload to stdout",
		Long: `Verify a signed in-toto statement wrapped in a DSSE envelope inside a standard Sigstore bundle.
Outputs the verified JSON statement to stdout.`,
		Example: `  # Verify an attestation using a local public key
  cosign-verify verify-attestation --bundle statement.bundle.json --key cosign.pub

  # Verify and assert the statement describes a specific local file
  cosign-verify verify-attestation --bundle statement.bundle.json --key cosign.pub payload.txt`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var payloadPath string
			if len(args) > 0 {
				payloadPath = args[0]
			}

			if vo.BundlePath == "" {
				return errors.New("--bundle is required")
			}

			if vo.KeyRef != "" && (vo.CertIdentity != "" || vo.CertIdentityRegexp != "") {
				return errors.New("cannot specify both --key and --certificate-identity options")
			}

			ctx := cmd.Context()
			ctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			return verifyBundle(ctx, vo, payloadPath, true)
		},
	}

	addCommonVerifyFlags(cmd, &vo)
	cmd.Flags().StringVar(&vo.PredicateType, "predicate-type", "custom", "specify a predicate type (slsaprovenance|slsaprovenance02|slsaprovenance1|link|spdx|spdxjson|cyclonedx|vuln|openvex|custom) or an URI")
	cmd.Flags().BoolVar(&vo.CheckClaims, "check-claims", true, "if true, verifies the digest exists in the in-toto subject (using either the provided digest and digest algorithm or the provided blob's sha256 digest). If false, only the DSSE envelope is verified.")
	cmd.Flags().DurationVarP(&timeout, "timeout", "t", 3*time.Minute, "timeout for commands")

	return cmd
}

func addCommonVerifyFlags(cmd *cobra.Command, vo *VerifyOpts) {
	// Bypasses KMS/Kubernetes options in the help text since they are stripped
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
