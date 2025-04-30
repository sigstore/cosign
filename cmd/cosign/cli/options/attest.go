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
	"strings"

	"github.com/spf13/cobra"
)

// AttestOptions is the top level wrapper for the attest command.
type AttestOptions struct {
	Key                     string
	Cert                    string
	CertChain               string
	NoUpload                bool
	Replace                 bool
	SkipConfirmation        bool
	TlogUpload              bool
	TSAClientCACert         string
	TSAClientCert           string
	TSAClientKey            string
	TSAServerName           string
	TSAServerURL            string
	RekorEntryType          string
	RecordCreationTimestamp bool
	NewBundleFormat         bool

	Rekor       RekorOptions
	Fulcio      FulcioOptions
	OIDC        OIDCOptions
	SecurityKey SecurityKeyOptions
	Predicate   PredicateLocalOptions
	Registry    RegistryOptions
}

var _ Interface = (*AttestOptions)(nil)

// AddFlags implements Interface
func (o *AttestOptions) AddFlags(cmd *cobra.Command) {
	o.SecurityKey.AddFlags(cmd)
	o.Predicate.AddFlags(cmd)
	o.Fulcio.AddFlags(cmd)
	o.OIDC.AddFlags(cmd)
	o.Rekor.AddFlags(cmd)
	o.Registry.AddFlags(cmd)

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

	cmd.Flags().BoolVar(&o.NoUpload, "no-upload", false,
		"do not upload the generated attestation")

	cmd.Flags().BoolVarP(&o.Replace, "replace", "", false,
		"")

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

	cmd.Flags().BoolVar(&o.RecordCreationTimestamp, "record-creation-timestamp", false,
		"set the createdAt timestamp in the attestation artifact to the time it was created; by default, cosign sets this to the zero value")

	cmd.Flags().BoolVar(&o.NewBundleFormat, "new-bundle-format", false, "attach a Sigstore bundle using OCI referrers API")
}
