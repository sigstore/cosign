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
	"strings"

	"github.com/spf13/cobra"
)

// AttestOptions is the top level wrapper for the attest command.
type AttestBlobOptions struct {
	Key              string
	Cert             string
	CertChain        string
	IssueCertificate bool

	SkipConfirmation     bool
	TlogUpload           bool
	TSAClientCACert      string
	TSAClientCert        string
	TSAClientKey         string
	TSAServerName        string
	TSAServerURL         string
	RFC3161TimestampPath string

	Hash      string
	Predicate PredicateLocalOptions

	OutputSignature   string
	OutputAttestation string
	OutputCertificate string
	BundlePath        string
	NewBundleFormat   bool

	RekorEntryType string

	Rekor       RekorOptions
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
	o.Rekor.AddFlags(cmd)
	o.Fulcio.AddFlags(cmd)
	o.OIDC.AddFlags(cmd)
	o.SecurityKey.AddFlags(cmd)

	cmd.Flags().StringVar(&o.Key, "key", "",
		"path to the private key file, KMS URI or Kubernetes Secret")
	_ = cmd.MarkFlagFilename("key", privateKeyExts...)

	cmd.Flags().StringVar(&o.Cert, "certificate", "",
		"path to the X.509 certificate in PEM format to include in the OCI Signature")
	_ = cmd.MarkFlagFilename("certificate", certificateExts...)

	cmd.Flags().StringVar(&o.CertChain, "certificate-chain", "",
		"path to a list of CA X.509 certificates in PEM format which will be needed "+
			"when building the certificate chain for the signing certificate. "+
			"Must start with the parent intermediate CA certificate of the "+
			"signing certificate and end with the root certificate. Included in the OCI Signature")
	_ = cmd.MarkFlagFilename("certificate-chain", certificateExts...)

	cmd.Flags().StringVar(&o.OutputSignature, "output-signature", "",
		"write the signature to FILE")
	_ = cmd.MarkFlagFilename("output-signature", signatureExts...)

	cmd.Flags().StringVar(&o.OutputAttestation, "output-attestation", "",
		"write the attestation to FILE")
	// _ = cmd.MarkFlagFilename("output-attestation") // no typical extensions

	cmd.Flags().StringVar(&o.OutputCertificate, "output-certificate", "",
		"write the certificate to FILE")
	_ = cmd.MarkFlagFilename("key", certificateExts...)

	cmd.Flags().StringVar(&o.BundlePath, "bundle", "",
		"write everything required to verify the blob to a FILE")
	_ = cmd.MarkFlagFilename("bundle", bundleExts...)

	// TODO: have this default to true as a breaking change
	cmd.Flags().BoolVar(&o.NewBundleFormat, "new-bundle-format", false,
		"output bundle in new format that contains all verification material")

	// TODO: have this default to true as a breaking change
	cmd.Flags().BoolVar(&o.UseSigningConfig, "use-signing-config", false,
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

	cmd.Flags().BoolVar(&o.TlogUpload, "tlog-upload", true,
		"whether or not to upload to the tlog")

	cmd.Flags().StringVar(&o.RekorEntryType, "rekor-entry-type", rekorEntryTypes[0],
		"specifies the type to be used for a rekor entry upload ("+strings.Join(rekorEntryTypes, "|")+")")
	_ = cmd.RegisterFlagCompletionFunc("rekor-entry-type", cobra.FixedCompletions(rekorEntryTypes, cobra.ShellCompDirectiveNoFileComp))

	cmd.Flags().StringVar(&o.TSAClientCACert, "timestamp-client-cacert", "",
		"path to the X.509 CA certificate file in PEM format to be used for the connection to the TSA Server")

	cmd.Flags().StringVar(&o.TSAClientCert, "timestamp-client-cert", "",
		"path to the X.509 certificate file in PEM format to be used for the connection to the TSA Server")

	cmd.Flags().StringVar(&o.TSAClientKey, "timestamp-client-key", "",
		"path to the X.509 private key file in PEM format to be used, together with the 'timestamp-client-cert' value, for the connection to the TSA Server")

	cmd.Flags().StringVar(&o.TSAServerName, "timestamp-server-name", "",
		"SAN name to use as the 'ServerName' tls.Config field to verify the mTLS connection to the TSA Server")

	cmd.Flags().StringVar(&o.TSAServerURL, "timestamp-server-url", "",
		"url to the Timestamp RFC3161 server, default none. Must be the path to the API to request timestamp responses, e.g. https://freetsa.org/tsr")
	_ = cmd.RegisterFlagCompletionFunc("timestamp-server-url", cobra.NoFileCompletions)

	cmd.Flags().StringVar(&o.RFC3161TimestampPath, "rfc3161-timestamp-bundle", "",
		"path to an RFC 3161 timestamp bundle FILE")
	// _ = cmd.MarkFlagFilename("rfc3161-timestamp-bundle") // no typical extensions

	cmd.Flags().BoolVar(&o.IssueCertificate, "issue-certificate", false,
		"issue a code signing certificate from Fulcio, even if a key is provided")
}
