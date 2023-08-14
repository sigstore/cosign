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
	"github.com/spf13/cobra"
)

// SignOptions is the top level wrapper for the sign command.
type SignOptions struct {
	Key                   string
	Cert                  string
	CertChain             string
	Upload                bool
	Output                string // deprecated: TODO remove when the output flag is fully deprecated
	OutputSignature       string // TODO: this should be the root output file arg.
	OutputPayload         string
	OutputCertificate     string
	PayloadPath           string
	Recursive             bool
	Attachment            string
	SkipConfirmation      bool
	TlogUpload            bool
	TSAClientCACert       string
	TSAClientCert         string
	TSAClientKey          string
	TSAServerName         string
	TSAServerURL          string
	IssueCertificate      bool
	SignContainerIdentity string

	Rekor       RekorOptions
	Fulcio      FulcioOptions
	OIDC        OIDCOptions
	SecurityKey SecurityKeyOptions
	AnnotationOptions
	Registry             RegistryOptions
	RegistryExperimental RegistryExperimentalOptions
}

var _ Interface = (*SignOptions)(nil)

// AddFlags implements Interface
func (o *SignOptions) AddFlags(cmd *cobra.Command) {
	o.Rekor.AddFlags(cmd)
	o.Fulcio.AddFlags(cmd)
	o.OIDC.AddFlags(cmd)
	o.SecurityKey.AddFlags(cmd)
	o.AnnotationOptions.AddFlags(cmd)
	o.Registry.AddFlags(cmd)
	o.RegistryExperimental.AddFlags(cmd)

	cmd.Flags().StringVar(&o.Key, "key", "",
		"path to the private key file, KMS URI or Kubernetes Secret")
	_ = cmd.Flags().SetAnnotation("key", cobra.BashCompFilenameExt, []string{})

	cmd.Flags().StringVar(&o.Cert, "certificate", "",
		"path to the X.509 certificate in PEM format to include in the OCI Signature")
	_ = cmd.Flags().SetAnnotation("certificate", cobra.BashCompFilenameExt, []string{"cert"})

	cmd.Flags().StringVar(&o.CertChain, "certificate-chain", "",
		"path to a list of CA X.509 certificates in PEM format which will be needed "+
			"when building the certificate chain for the signing certificate. "+
			"Must start with the parent intermediate CA certificate of the "+
			"signing certificate and end with the root certificate. Included in the OCI Signature")
	_ = cmd.Flags().SetAnnotation("certificate-chain", cobra.BashCompFilenameExt, []string{"cert"})

	cmd.Flags().BoolVar(&o.Upload, "upload", true,
		"whether to upload the signature")

	cmd.Flags().StringVar(&o.OutputSignature, "output-signature", "",
		"write the signature to FILE")
	_ = cmd.Flags().SetAnnotation("output-signature", cobra.BashCompFilenameExt, []string{})
	cmd.Flags().StringVar(&o.OutputPayload, "output-payload", "",
		"write the signed payload to FILE")
	_ = cmd.Flags().SetAnnotation("output-payload", cobra.BashCompFilenameExt, []string{})

	cmd.Flags().StringVar(&o.OutputCertificate, "output-certificate", "",
		"write the certificate to FILE")
	_ = cmd.Flags().SetAnnotation("output-certificate", cobra.BashCompFilenameExt, []string{})

	cmd.Flags().StringVar(&o.PayloadPath, "payload", "",
		"path to a payload file to use rather than generating one")
	_ = cmd.Flags().SetAnnotation("payload", cobra.BashCompFilenameExt, []string{})

	cmd.Flags().BoolVarP(&o.Recursive, "recursive", "r", false,
		"if a multi-arch image is specified, additionally sign each discrete image")

	cmd.Flags().StringVar(&o.Attachment, "attachment", "",
		"related image attachment to sign (sbom), default none")

	cmd.Flags().BoolVarP(&o.SkipConfirmation, "yes", "y", false,
		"skip confirmation prompts for non-destructive operations")

	cmd.Flags().BoolVar(&o.TlogUpload, "tlog-upload", true,
		"whether or not to upload to the tlog")

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

	_ = cmd.Flags().SetAnnotation("certificate", cobra.BashCompFilenameExt, []string{"cert"})

	cmd.Flags().BoolVar(&o.IssueCertificate, "issue-certificate", false,
		"issue a code signing certificate from Fulcio, even if a key is provided")

	cmd.Flags().StringVar(&o.SignContainerIdentity, "sign-container-identity", "",
		"manually set the .critical.docker-reference field for the signed identity, which is useful when image proxies are being used where the pull reference should match the signature")
}
