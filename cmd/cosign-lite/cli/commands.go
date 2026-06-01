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
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sigstore/cosign/v3/pkg/cosign"
	pb_go_v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/signature"
	tufv1 "github.com/sigstore/sigstore/pkg/tuf"
	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	var rootCmd = &cobra.Command{
		Use:               "cosign-lite",
		Short:             "cosign-lite is a lightweight Sigstore signing and verification utility",
		DisableAutoGenTag: true,
	}
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	rootCmd.AddCommand(
		Initialize(),
		GenerateKeyPair(),
		Sign(),
		Attest(),
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

func GenerateKeyPair() *cobra.Command {
	var outputKeyPrefix string

	cmd := &cobra.Command{
		Use:   "generate-key-pair",
		Short: "Generate a local password-encrypted key pair",
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := generateKeyPair(outputKeyPrefix, getPass); err != nil {
				return err
			}
			fmt.Println("Private key written to", outputKeyPrefix+".key")
			fmt.Println("Public key written to", outputKeyPrefix+".pub")
			return nil
		},
	}

	cmd.Flags().StringVar(&outputKeyPrefix, "output-key-prefix", "cosign", "name used for generated .pub and .key files")

	return cmd
}

func Sign() *cobra.Command {
	var keyRef string
	var certPath string
	var certChainPath string
	var tlogUpload bool
	var bundlePath string
	var signingConfigPath string
	var trustedRootPath string
	var identityToken string
	var fulcioAuthFlow string
	var oidcClientID string
	var oidcClientSecretFile string
	var oidcRedirectURL string
	var oidcProvider string
	var oidcDisableAmbientProviders bool
	var signingAlgorithm string
	var issueCertificate bool
	var skipConfirmation bool
	var timeout time.Duration

	cmd := &cobra.Command{
		Use:   "sign <payload>",
		Short: "Sign the supplied payload blob and generate a Sigstore bundle",
		Long: `Sign the supplied payload blob using a Sigstore OIDC identity token (keyless flow)
or a local on-disk key pair, and generate a standardized Sigstore verification bundle.`,
		Example: `  # Sign a payload keylessly using OIDC and write the bundle to a file
  cosign-lite sign --bundle payload.bundle.json payload.txt

  # Sign a payload using a local private key and write the bundle to a file
  cosign-lite sign --key cosign.key --bundle payload.bundle.json payload.txt

  # Sign a payload using OIDC without uploading to the transparency log (Rekor)
  cosign-lite sign --bundle payload.bundle.json --tlog-upload=false payload.txt`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			payloadPath := args[0]

			if bundlePath == "" {
				return errors.New("--bundle is required")
			}

			if signingConfigPath != "" && !tlogUpload {
				return errors.New("--tlog-upload=false is not supported with --signing-config. Provide a signing config with --signing-config without a transparency log service")
			}

			var clientSecret string
			if oidcClientSecretFile != "" {
				clientSecretBytes, err := os.ReadFile(oidcClientSecretFile)
				if err != nil {
					return fmt.Errorf("reading OIDC client secret: %w", err)
				}
				clientSecret = strings.TrimSpace(string(clientSecretBytes))
			}

			ctx := cmd.Context()
			ro := &RootOptions{Timeout: timeout}
			ko := KeyOpts{
				KeyRef:                         keyRef,
				BundlePath:                     bundlePath,
				PassFunc:                       getPass,
				SkipConfirmation:               skipConfirmation,
				IDToken:                        identityToken,
				OIDCDisableProviders:           oidcDisableAmbientProviders,
				OIDCProvider:                   oidcProvider,
				FulcioAuthFlow:                 fulcioAuthFlow,
				OIDCClientID:                   oidcClientID,
				OIDCClientSecret:               clientSecret,
				OIDCRedirectURL:                oidcRedirectURL,
				SigningAlgorithm:               signingAlgorithm,
				IssueCertificateForExistingKey: issueCertificate,
			}

			if signingConfigPath != "" {
				sc, err := root.NewSigningConfigFromPath(signingConfigPath)
				if err != nil {
					return fmt.Errorf("loading signing config: %w", err)
				}
				ko.SigningConfig = sc
			}

			if trustedRootPath != "" {
				tr, err := root.NewTrustedRootFromPath(trustedRootPath)
				if err != nil {
					return fmt.Errorf("loading trusted root: %w", err)
				}
				ko.TrustedMaterial = tr
			}

			return signBundle(ctx, ro, ko, payloadPath, certPath, certChainPath, tlogUpload, false)
		},
	}

	cmd.Flags().StringVar(&keyRef, "key", "", "path to the private key file")
	_ = cmd.MarkFlagFilename("key", "key", "pem")

	cmd.Flags().StringVar(&certPath, "cert", "", "path to the X.509 certificate for signing attestation")
	_ = cmd.MarkFlagFilename("cert", "pem", "crt")

	cmd.Flags().StringVar(&certChainPath, "cert-chain", "", "path to a list of CA X.509 certificates in PEM format which will be needed when building the certificate chain for the signed attestation. Must start with the parent intermediate CA certificate of the signing certificate and end with the root certificate.")
	_ = cmd.MarkFlagFilename("cert-chain", "pem", "crt")

	cmd.Flags().BoolVar(&tlogUpload, "tlog-upload", true, "whether or not to upload to the tlog")
	cmd.Flags().StringVar(&bundlePath, "bundle", "", "write everything required to verify the blob to a FILE")
	_ = cmd.MarkFlagFilename("bundle", "bundle", "json")

	cmd.Flags().StringVar(&signingConfigPath, "signing-config", "", "path to a signing config file. Must provide --bundle, which will output verification material in the new format")
	_ = cmd.MarkFlagFilename("signing-config", "json")

	cmd.Flags().StringVar(&trustedRootPath, "trusted-root", "", "optional path to a TrustedRoot JSON file to verify a signature after signing")
	_ = cmd.MarkFlagFilename("trusted-root", "json")

	cmd.Flags().StringVar(&identityToken, "identity-token", "", "identity token to use for certificate from fulcio. the token or a path to a file containing the token is accepted.")
	cmd.Flags().StringVar(&fulcioAuthFlow, "fulcio-auth-flow", "", "fulcio interactive oauth2 flow to use for certificate from fulcio. Defaults to determining the flow based on the runtime environment. (options) normal|device|token|client_credentials")
	cmd.Flags().StringVar(&oidcClientID, "oidc-client-id", "sigstore", "OIDC client ID for application")
	cmd.Flags().StringVar(&oidcClientSecretFile, "oidc-client-secret-file", "", "Path to file containing OIDC client secret for application")
	_ = cmd.MarkFlagFilename("oidc-client-secret-file")

	cmd.Flags().StringVar(&oidcRedirectURL, "oidc-redirect-url", "", "OIDC redirect URL (Optional). The default oidc-redirect-url is 'http://localhost:0/auth/callback'.")
	cmd.Flags().StringVar(&oidcProvider, "oidc-provider", "", "Specify the provider to get the OIDC token from (Optional). If unset, all options will be tried. Options include: [spiffe, google, github-actions, filesystem, buildkite-agent]")
	cmd.Flags().BoolVar(&oidcDisableAmbientProviders, "oidc-disable-ambient-providers", false, "Disable ambient OIDC providers. When true, ambient credentials will not be read")
	cmd.Flags().BoolVarP(&skipConfirmation, "yes", "y", false, "skip confirmation prompts for non-destructive operations")

	keyAlgorithmTypes := cosign.GetSupportedAlgorithms()
	keyAlgorithmHelp := fmt.Sprintf("signing algorithm to use for signing/hashing (allowed %s)", strings.Join(keyAlgorithmTypes, ", "))
	defaultKeyFlag, _ := signature.FormatSignatureAlgorithmFlag(pb_go_v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256)
	cmd.Flags().StringVar(&signingAlgorithm, "signing-algorithm", defaultKeyFlag, keyAlgorithmHelp)
	cmd.Flags().BoolVar(&issueCertificate, "issue-certificate", false, "issue a code signing certificate from Fulcio, even if a key is provided")
	cmd.Flags().DurationVarP(&timeout, "timeout", "t", 3*time.Minute, "timeout for commands")

	return cmd
}

func Attest() *cobra.Command {
	var keyRef string
	var certPath string
	var certChainPath string
	var tlogUpload bool
	var bundlePath string
	var signingConfigPath string
	var trustedRootPath string
	var identityToken string
	var fulcioAuthFlow string
	var oidcClientID string
	var oidcClientSecretFile string
	var oidcRedirectURL string
	var oidcProvider string
	var oidcDisableAmbientProviders bool
	var signingAlgorithm string
	var issueCertificate bool
	var skipConfirmation bool
	var timeout time.Duration

	cmd := &cobra.Command{
		Use:   "attest <statement-file>",
		Short: "Sign the supplied in-toto statement and generate a Sigstore bundle with a DSSE envelope",
		Long: `Sign a pre-constructed in-toto statement JSON using Sigstore OIDC identity token (keyless flow)
or a local on-disk key pair, wrapping it in a DSSE envelope, and generate a standardized Sigstore verification bundle.`,
		Example: `  # Sign a statement keylessly using OIDC and write the bundle to a file
  cosign-lite attest --bundle statement.bundle.json statement.json

  # Sign a statement using a local private key and write the bundle to a file
  cosign-lite attest --key cosign.key --bundle statement.bundle.json statement.json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			payloadPath := args[0]

			if bundlePath == "" {
				return errors.New("--bundle is required")
			}

			if signingConfigPath != "" && !tlogUpload {
				return errors.New("--tlog-upload=false is not supported with --signing-config. Provide a signing config with --signing-config without a transparency log service")
			}

			var clientSecret string
			if oidcClientSecretFile != "" {
				clientSecretBytes, err := os.ReadFile(oidcClientSecretFile)
				if err != nil {
					return fmt.Errorf("reading OIDC client secret: %w", err)
				}
				clientSecret = strings.TrimSpace(string(clientSecretBytes))
			}

			ctx := cmd.Context()
			ro := &RootOptions{Timeout: timeout}
			ko := KeyOpts{
				KeyRef:                         keyRef,
				BundlePath:                     bundlePath,
				PassFunc:                       getPass,
				SkipConfirmation:               skipConfirmation,
				IDToken:                        identityToken,
				OIDCDisableProviders:           oidcDisableAmbientProviders,
				OIDCProvider:                   oidcProvider,
				FulcioAuthFlow:                 fulcioAuthFlow,
				OIDCClientID:                   oidcClientID,
				OIDCClientSecret:               clientSecret,
				OIDCRedirectURL:                oidcRedirectURL,
				SigningAlgorithm:               signingAlgorithm,
				IssueCertificateForExistingKey: issueCertificate,
			}

			if signingConfigPath != "" {
				sc, err := root.NewSigningConfigFromPath(signingConfigPath)
				if err != nil {
					return fmt.Errorf("loading signing config: %w", err)
				}
				ko.SigningConfig = sc
			}

			if trustedRootPath != "" {
				tr, err := root.NewTrustedRootFromPath(trustedRootPath)
				if err != nil {
					return fmt.Errorf("loading trusted root: %w", err)
				}
				ko.TrustedMaterial = tr
			}

			return signBundle(ctx, ro, ko, payloadPath, certPath, certChainPath, tlogUpload, true)
		},
	}

	cmd.Flags().StringVar(&keyRef, "key", "", "path to the private key file")
	_ = cmd.MarkFlagFilename("key", "key", "pem")

	cmd.Flags().StringVar(&certPath, "cert", "", "path to the X.509 certificate for signing attestation")
	_ = cmd.MarkFlagFilename("cert", "pem", "crt")

	cmd.Flags().StringVar(&certChainPath, "cert-chain", "", "path to a list of CA X.509 certificates in PEM format which will be needed when building the certificate chain for the signed attestation. Must start with the parent intermediate CA certificate of the signing certificate and end with the root certificate.")
	_ = cmd.MarkFlagFilename("cert-chain", "pem", "crt")

	cmd.Flags().BoolVar(&tlogUpload, "tlog-upload", true, "whether or not to upload to the tlog")
	cmd.Flags().StringVar(&bundlePath, "bundle", "", "write everything required to verify the blob to a FILE")
	_ = cmd.MarkFlagFilename("bundle", "bundle", "json")

	cmd.Flags().StringVar(&signingConfigPath, "signing-config", "", "path to a signing config file. Must provide --bundle, which will output verification material in the new format")
	_ = cmd.MarkFlagFilename("signing-config", "json")

	cmd.Flags().StringVar(&trustedRootPath, "trusted-root", "", "optional path to a TrustedRoot JSON file to verify a signature after signing")
	_ = cmd.MarkFlagFilename("trusted-root", "json")

	cmd.Flags().StringVar(&identityToken, "identity-token", "", "identity token to use for certificate from fulcio. the token or a path to a file containing the token is accepted.")
	cmd.Flags().StringVar(&fulcioAuthFlow, "fulcio-auth-flow", "", "fulcio interactive oauth2 flow to use for certificate from fulcio. Defaults to determining the flow based on the runtime environment. (options) normal|device|token|client_credentials")
	cmd.Flags().StringVar(&oidcClientID, "oidc-client-id", "sigstore", "OIDC client ID for application")
	cmd.Flags().StringVar(&oidcClientSecretFile, "oidc-client-secret-file", "", "Path to file containing OIDC client secret for application")
	_ = cmd.MarkFlagFilename("oidc-client-secret-file")

	cmd.Flags().StringVar(&oidcRedirectURL, "oidc-redirect-url", "", "OIDC redirect URL (Optional). The default oidc-redirect-url is 'http://localhost:0/auth/callback'.")
	cmd.Flags().StringVar(&oidcProvider, "oidc-provider", "", "Specify the provider to get the OIDC token from (Optional). If unset, all options will be tried. Options include: [spiffe, google, github-actions, filesystem, buildkite-agent]")
	cmd.Flags().BoolVar(&oidcDisableAmbientProviders, "oidc-disable-ambient-providers", false, "Disable ambient OIDC providers. When true, ambient credentials will not be read")
	cmd.Flags().BoolVarP(&skipConfirmation, "yes", "y", false, "skip confirmation prompts for non-destructive operations")

	keyAlgorithmTypes := cosign.GetSupportedAlgorithms()
	keyAlgorithmHelp := fmt.Sprintf("signing algorithm to use for signing/hashing (allowed %s)", strings.Join(keyAlgorithmTypes, ", "))
	defaultKeyFlag, _ := signature.FormatSignatureAlgorithmFlag(pb_go_v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256)
	cmd.Flags().StringVar(&signingAlgorithm, "signing-algorithm", defaultKeyFlag, keyAlgorithmHelp)
	cmd.Flags().BoolVar(&issueCertificate, "issue-certificate", false, "issue a code signing certificate from Fulcio, even if a key is provided")
	cmd.Flags().DurationVarP(&timeout, "timeout", "t", 3*time.Minute, "timeout for commands")

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
  cosign-lite verify --bundle payload.bundle.json --key cosign.pub payload.txt

  # Verify a payload keylessly using an OIDC identity subject and issuer
  cosign-lite verify --bundle payload.bundle.json \
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
  cosign-lite verify-attestation --bundle statement.bundle.json --key cosign.pub

  # Verify and assert the statement describes a specific local file
  cosign-lite verify-attestation --bundle statement.bundle.json --key cosign.pub payload.txt`,
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
