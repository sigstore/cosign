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
	"fmt"
	"strings"

	"github.com/sigstore/cosign/v3/pkg/cosign"
	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/spf13/cobra"
)

// SignBlobOptions is the top level wrapper for the sign-blob command.
// The new output-certificate flag is only in use when COSIGN_EXPERIMENTAL is enabled
type SignBlobOptions struct {
	Key                  string
	Base64Output         bool
	Output               string // deprecated: TODO remove when the output flag is fully deprecated
	OutputSignature      string // TODO: this should be the root output file arg.
	OutputCertificate    string
	SecurityKey          SecurityKeyOptions
	Fulcio               FulcioOptions
	Rekor                RekorOptions
	OIDC                 OIDCOptions
	Registry             RegistryOptions
	BundlePath           string
	NewBundleFormat      bool
	SkipConfirmation     bool
	TlogUpload           bool
	TSAClientCACert      string
	TSAClientCert        string
	TSAClientKey         string
	TSAServerName        string
	TSAServerURL         string
	RFC3161TimestampPath string
	IssueCertificate     bool
	SigningAlgorithm     string

	UseSigningConfig  bool
	SigningConfigPath string
	TrustedRootPath   string
}

var _ Interface = (*SignBlobOptions)(nil)

// AddFlags implements Interface
func (o *SignBlobOptions) AddFlags(cmd *cobra.Command) {
	o.SecurityKey.AddFlags(cmd)
	o.Fulcio.AddFlags(cmd)
	o.Rekor.AddFlags(cmd)
	o.OIDC.AddFlags(cmd)

	cmd.Flags().StringVar(&o.Key, "key", "",
		"path to the private key file, KMS URI or Kubernetes Secret")
	_ = cmd.MarkFlagFilename("key", privateKeyExts...)

	cmd.Flags().BoolVar(&o.Base64Output, "b64", true,
		"whether to base64 encode the output")

	cmd.Flags().StringVar(&o.OutputSignature, "output-signature", "",
		"write the signature to FILE")
	_ = cmd.MarkFlagFilename("output-signature", signatureExts...)

	// TODO: remove when output flag is fully deprecated
	cmd.Flags().StringVar(&o.Output, "output", "", "write the signature to FILE")
	_ = cmd.MarkFlagFilename("output", signatureExts...)

	cmd.Flags().StringVar(&o.OutputCertificate, "output-certificate", "",
		"write the certificate to FILE")
	_ = cmd.MarkFlagFilename("output-certificate", certificateExts...)

	cmd.Flags().StringVar(&o.BundlePath, "bundle", "",
		"write everything required to verify the blob to a FILE")
	_ = cmd.MarkFlagFilename("bundle", bundleExts...)

	cmd.Flags().BoolVar(&o.NewBundleFormat, "new-bundle-format", true,
		"output bundle in new format that contains all verification material")

	cmd.Flags().BoolVar(&o.UseSigningConfig, "use-signing-config", true,
		"whether to use a TUF-provided signing config for the service URLs. Must provide --bundle, which will output verification material in the new format")

	cmd.Flags().StringVar(&o.SigningConfigPath, "signing-config", "",
		"path to a signing config file. Must provide --bundle, which will output verification material in the new format")

	cmd.MarkFlagsMutuallyExclusive("use-signing-config", "signing-config")

	cmd.Flags().StringVar(&o.TrustedRootPath, "trusted-root", "",
		"optional path to a TrustedRoot JSON file to verify a signature after signing")

	cmd.Flags().BoolVarP(&o.SkipConfirmation, "yes", "y", false,
		"skip confirmation prompts for non-destructive operations")

	cmd.Flags().BoolVar(&o.TlogUpload, "tlog-upload", true,
		"whether or not to upload to the tlog")
	_ = cmd.Flags().MarkDeprecated("tlog-upload", "prefer using a --signing-config file with no transparency log services")

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

	cmd.Flags().StringVar(&o.TSAServerURL, "timestamp-server-url", "",
		"url to the Timestamp RFC3161 server, default none. Must be the path to the API to request timestamp responses, e.g. https://freetsa.org/tsr")
	_ = cmd.RegisterFlagCompletionFunc("timestamp-server-url", cobra.NoFileCompletions)

	cmd.Flags().StringVar(&o.RFC3161TimestampPath, "rfc3161-timestamp", "",
		"write the RFC3161 timestamp to a file")
	// _ = cmd.MarkFlagFilename("rfc3161-timestamp") // no typical extensions

	cmd.Flags().BoolVar(&o.IssueCertificate, "issue-certificate", false,
		"issue a code signing certificate from Fulcio, even if a key is provided")

	keyAlgorithmTypes := cosign.GetSupportedAlgorithms()
	keyAlgorithmHelp := fmt.Sprintf("signing algorithm to use for signing/hashing (allowed %s)", strings.Join(keyAlgorithmTypes, ", "))
	defaultKeyFlag, _ := signature.FormatSignatureAlgorithmFlag(v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256)
	cmd.Flags().StringVar(&o.SigningAlgorithm, "signing-algorithm", defaultKeyFlag, keyAlgorithmHelp)
}
