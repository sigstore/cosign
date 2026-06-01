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
	"github.com/spf13/cobra"
)

type RootOptions struct {
	Timeout time.Duration
}

type KeyOpts struct {
	KeyRef                         string
	BundlePath                     string
	SkipConfirmation               bool
	IDToken                        string
	OIDCDisableProviders           bool
	OIDCProvider                   string
	FulcioAuthFlow                 string
	OIDCClientID                   string
	OIDCClientSecret               string
	OIDCRedirectURL                string
	IssueCertificateForExistingKey bool
	SigningAlgorithm               string
	DefaultLoadOptions             *[]signature.LoadOption
	PassFunc                       func(bool) ([]byte, error)
	TrustedMaterial                root.TrustedMaterial
	SigningConfig                  *root.SigningConfig
}

type SignOptions struct {
	KeyRef                      string
	CertPath                    string
	CertChainPath               string
	TlogUpload                  bool
	BundlePath                  string
	SigningConfigPath           string
	TrustedRootPath             string
	IdentityToken               string
	FulcioAuthFlow              string
	OIDCClientID                string
	OIDCClientSecretFile        string
	OIDCRedirectURL             string
	OIDCProvider                string
	OIDCDisableAmbientProviders bool
	SigningAlgorithm            string
	IssueCertificate            bool
	SkipConfirmation            bool
	Timeout                     time.Duration
}

func (o *SignOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.KeyRef, "key", "", "path to the private key file")
	_ = cmd.MarkFlagFilename("key", "key", "pem")

	cmd.Flags().StringVar(&o.CertPath, "cert", "", "path to the X.509 certificate for signing attestation")
	_ = cmd.MarkFlagFilename("cert", "pem", "crt")

	cmd.Flags().StringVar(&o.CertChainPath, "cert-chain", "", "path to a list of CA X.509 certificates in PEM format which will be needed when building the certificate chain for the signed attestation. Must start with the parent intermediate CA certificate of the signing certificate and end with the root certificate.")
	_ = cmd.MarkFlagFilename("cert-chain", "pem", "crt")

	cmd.Flags().BoolVar(&o.TlogUpload, "tlog-upload", true, "whether or not to upload to the tlog")
	cmd.Flags().StringVar(&o.BundlePath, "bundle", "", "write everything required to verify the blob to a FILE")
	_ = cmd.MarkFlagFilename("bundle", "bundle", "json")

	cmd.Flags().StringVar(&o.SigningConfigPath, "signing-config", "", "path to a signing config file. Must provide --bundle, which will output verification material in the new format")
	_ = cmd.MarkFlagFilename("signing-config", "json")

	cmd.Flags().StringVar(&o.TrustedRootPath, "trusted-root", "", "optional path to a TrustedRoot JSON file to verify a signature after signing")
	_ = cmd.MarkFlagFilename("trusted-root", "json")

	cmd.Flags().StringVar(&o.IdentityToken, "identity-token", "", "identity token to use for certificate from fulcio. the token or a path to a file containing the token is accepted.")
	cmd.Flags().StringVar(&o.FulcioAuthFlow, "fulcio-auth-flow", "", "fulcio interactive oauth2 flow to use for certificate from fulcio. Defaults to determining the flow based on the runtime environment. (options) normal|device|token|client_credentials")
	cmd.Flags().StringVar(&o.OIDCClientID, "oidc-client-id", "sigstore", "OIDC client ID for application")
	cmd.Flags().StringVar(&o.OIDCClientSecretFile, "oidc-client-secret-file", "", "Path to file containing OIDC client secret for application")
	_ = cmd.MarkFlagFilename("oidc-client-secret-file")

	cmd.Flags().StringVar(&o.OIDCRedirectURL, "oidc-redirect-url", "", "OIDC redirect URL (Optional). The default oidc-redirect-url is 'http://localhost:0/auth/callback'.")
	cmd.Flags().StringVar(&o.OIDCProvider, "oidc-provider", "", "Specify the provider to get the OIDC token from (Optional). If unset, all options will be tried. Options include: [spiffe, google, github-actions, filesystem, buildkite-agent]")
	cmd.Flags().BoolVar(&o.OIDCDisableAmbientProviders, "oidc-disable-ambient-providers", false, "Disable ambient OIDC providers. When true, ambient credentials will not be read")
	cmd.Flags().BoolVarP(&o.SkipConfirmation, "yes", "y", false, "skip confirmation prompts for non-destructive operations")

	keyAlgorithmTypes := cosign.GetSupportedAlgorithms()
	keyAlgorithmHelp := fmt.Sprintf("signing algorithm to use for signing/hashing (allowed %s)", strings.Join(keyAlgorithmTypes, ", "))
	defaultKeyFlag, _ := signature.FormatSignatureAlgorithmFlag(pb_go_v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256)
	cmd.Flags().StringVar(&o.SigningAlgorithm, "signing-algorithm", defaultKeyFlag, keyAlgorithmHelp)
	cmd.Flags().BoolVar(&o.IssueCertificate, "issue-certificate", false, "issue a code signing certificate from Fulcio, even if a key is provided")
	cmd.Flags().DurationVarP(&o.Timeout, "timeout", "t", 3*time.Minute, "timeout for commands")
}

func (o *SignOptions) ToRootAndKeyOpts(passFunc func(bool) ([]byte, error)) (*RootOptions, KeyOpts, error) {
	if o.BundlePath == "" {
		return nil, KeyOpts{}, errors.New("--bundle is required")
	}

	if o.SigningConfigPath != "" && !o.TlogUpload {
		return nil, KeyOpts{}, errors.New("--tlog-upload=false is not supported with --signing-config. Provide a signing config with --signing-config without a transparency log service")
	}

	var clientSecret string
	if o.OIDCClientSecretFile != "" {
		clientSecretBytes, err := os.ReadFile(o.OIDCClientSecretFile)
		if err != nil {
			return nil, KeyOpts{}, fmt.Errorf("reading OIDC client secret: %w", err)
		}
		clientSecret = strings.TrimSpace(string(clientSecretBytes))
	}

	ro := &RootOptions{Timeout: o.Timeout}
	ko := KeyOpts{
		KeyRef:                         o.KeyRef,
		BundlePath:                     o.BundlePath,
		PassFunc:                       passFunc,
		SkipConfirmation:               o.SkipConfirmation,
		IDToken:                        o.IdentityToken,
		OIDCDisableProviders:           o.OIDCDisableAmbientProviders,
		OIDCProvider:                   o.OIDCProvider,
		FulcioAuthFlow:                 o.FulcioAuthFlow,
		OIDCClientID:                   o.OIDCClientID,
		OIDCClientSecret:               clientSecret,
		OIDCRedirectURL:                o.OIDCRedirectURL,
		SigningAlgorithm:               o.SigningAlgorithm,
		IssueCertificateForExistingKey: o.IssueCertificate,
	}

	if o.SigningConfigPath != "" {
		sc, err := root.NewSigningConfigFromPath(o.SigningConfigPath)
		if err != nil {
			return nil, KeyOpts{}, fmt.Errorf("loading signing config: %w", err)
		}
		ko.SigningConfig = sc
	}

	if o.TrustedRootPath != "" {
		tr, err := root.NewTrustedRootFromPath(o.TrustedRootPath)
		if err != nil {
			return nil, KeyOpts{}, fmt.Errorf("loading trusted root: %w", err)
		}
		ko.TrustedMaterial = tr
	}

	return ro, ko, nil
}
