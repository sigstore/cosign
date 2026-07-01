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

// AttestOptions is the top level wrapper for the attest command.
type AttestBlobOptions struct {
	Key              string
	Cert             string
	CertChain        string
	IssueCertificate bool
	SkipConfirmation bool
	TSAClientCACert  string
	TSAClientCert    string
	TSAClientKey     string
	TSAServerName    string

	Hash      string
	Predicate PredicateLocalOptions

	BundlePath string

	Fulcio      FulcioOptions
	OIDC        OIDCOptions
	SecurityKey SecurityKeyOptions

	UseSigningConfig  bool
	SigningConfigPath string
	TrustedRootPath   string
}

var _ Interface = (*AttestOptions)(nil)

// AddFlags implements Interface
func (o *AttestBlobOptions) AddFlags(cmd *cobra.Command) {
	o.Predicate.AddFlags(cmd)
	o.Fulcio.AddFlags(cmd)
	o.OIDC.AddFlags(cmd)
	o.SecurityKey.AddFlags(cmd)

	cmd.Flags().StringVar(&o.Key, "key", "",
		"path to the private key file, KMS URI or Kubernetes Secret")
	_ = cmd.MarkFlagFilename("key", privateKeyExts...)

	cmd.Flags().StringVar(&o.Cert, "certificate", "",
		"path to the X.509 certificate for signing attestation")
	_ = cmd.MarkFlagFilename("certificate", certificateExts...)

	cmd.Flags().StringVar(&o.CertChain, "certificate-chain", "",
		"path to a list of CA X.509 certificates in PEM format which will be needed "+
			"when building the certificate chain for the signed attestation. "+
			"Must start with the parent intermediate CA certificate of the "+
			"signing certificate and end with the root certificate.")
	_ = cmd.MarkFlagFilename("certificate-chain", certificateExts...)

	cmd.Flags().StringVar(&o.BundlePath, "bundle", "",
		"write everything required to verify the blob to a FILE")
	_ = cmd.MarkFlagFilename("bundle", bundleExts...)

	cmd.Flags().BoolVar(&o.UseSigningConfig, "use-signing-config", true,
		"whether to use a TUF-provided signing config for the service URLs. Must provide --bundle, which will output verification material in the new format")

	cmd.Flags().StringVar(&o.SigningConfigPath, "signing-config", "",
		"path to a signing config file. Must provide --bundle, which will output verification material in the new format")

	cmd.MarkFlagsMutuallyExclusive("use-signing-config", "signing-config")

	cmd.Flags().StringVar(&o.TrustedRootPath, "trusted-root", "",
		"optional path to a TrustedRoot JSON file to verify a signature after signing")

	cmd.Flags().StringVar(&o.Hash, "hash", "",
		"hash of blob in hexadecimal (base16). Used if you want to sign an artifact stored elsewhere and have the hash")
	_ = cmd.RegisterFlagCompletionFunc("hash", cobra.NoFileCompletions)

	cmd.Flags().BoolVarP(&o.SkipConfirmation, "yes", "y", false,
		"skip confirmation prompts for non-destructive operations")

	cmd.Flags().StringVar(&o.TSAClientCACert, "timestamp-client-cacert", "",
		"path to the X.509 CA certificate file in PEM format to be used for the connection to the TSA Server")
	_ = cmd.MarkFlagFilename("timestamp-client-cacert", certificateExts...)

	cmd.Flags().StringVar(&o.TSAClientCert, "timestamp-client-cert", "",
		"path to the X.509 certificate file in PEM format to be used for the connection to the TSA Server")
	_ = cmd.MarkFlagFilename("timestamp-client-cert", certificateExts...)

	cmd.Flags().StringVar(&o.TSAClientKey, "timestamp-client-key", "",
		"path to the X.509 private key file in PEM format to be used, together with the 'timestamp-client-cert' value, for the connection to the TSA Server")
	_ = cmd.MarkFlagFilename("timestamp-client-key", privateKeyExts...)

	cmd.Flags().StringVar(&o.TSAServerName, "timestamp-server-name", "",
		"SAN name to use as the 'ServerName' tls.Config field to verify the mTLS connection to the TSA Server")
	_ = cmd.RegisterFlagCompletionFunc("timestamp-server-name", cobra.NoFileCompletions)

	cmd.Flags().BoolVar(&o.IssueCertificate, "issue-certificate", false,
		"issue a code signing certificate from Fulcio, even if a key is provided")
	_ = cmd.Flags().MarkDeprecated("issue-certificate", "support for this flag will be removed in the future")
}
