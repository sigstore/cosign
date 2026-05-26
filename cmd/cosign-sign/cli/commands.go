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
		Use:               "cosign-sign",
		Short:             "cosign-sign is a minimal signing utility for Sigstore",
		DisableAutoGenTag: true,
	}
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	rootCmd.AddCommand(
		Initialize(),
		GenerateKeyPair(),
		Sign(),
		Attest(),
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
  cosign-sign sign --bundle payload.bundle.json payload.txt

  # Sign a payload using a local private key and write the bundle to a file
  cosign-sign sign --key cosign.key --bundle payload.bundle.json payload.txt

  # Sign a payload using OIDC without uploading to the transparency log (Rekor)
  cosign-sign sign --bundle payload.bundle.json --tlog-upload=false payload.txt`,
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
  cosign-sign attest --bundle statement.bundle.json statement.json

  # Sign a statement using a local private key and write the bundle to a file
  cosign-sign attest --key cosign.key --bundle statement.bundle.json statement.json`,
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
