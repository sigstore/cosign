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
	Key       string
	Cert      string
	CertChain string

	SkipConfirmation     bool
	TlogUpload           bool
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
	_ = cmd.Flags().SetAnnotation("key", cobra.BashCompFilenameExt, []string{"key"})

	cmd.Flags().StringVar(&o.Cert, "certificate", "",
		"path to the X.509 certificate in PEM format to include in the OCI Signature")
	_ = cmd.Flags().SetAnnotation("certificate", cobra.BashCompFilenameExt, []string{"cert"})

	cmd.Flags().StringVar(&o.CertChain, "certificate-chain", "",
		"path to a list of CA X.509 certificates in PEM format which will be needed "+
			"when building the certificate chain for the signing certificate. "+
			"Must start with the parent intermediate CA certificate of the "+
			"signing certificate and end with the root certificate. Included in the OCI Signature")
	_ = cmd.Flags().SetAnnotation("certificate-chain", cobra.BashCompFilenameExt, []string{"cert"})

	cmd.Flags().StringVar(&o.OutputSignature, "output-signature", "",
		"write the signature to FILE")
	_ = cmd.Flags().SetAnnotation("output-signature", cobra.BashCompFilenameExt, []string{})

	cmd.Flags().StringVar(&o.OutputAttestation, "output-attestation", "",
		"write the attestation to FILE")

	cmd.Flags().StringVar(&o.OutputCertificate, "output-certificate", "",
		"write the certificate to FILE")
	_ = cmd.Flags().SetAnnotation("key", cobra.BashCompFilenameExt, []string{})

	cmd.Flags().StringVar(&o.BundlePath, "bundle", "",
		"write everything required to verify the blob to a FILE")
	_ = cmd.Flags().SetAnnotation("bundle", cobra.BashCompFilenameExt, []string{})

	// TODO: have this default to true as a breaking change
	cmd.Flags().BoolVar(&o.NewBundleFormat, "new-bundle-format", false,
		"output bundle in new format that contains all verification material")

	cmd.Flags().StringVar(&o.Hash, "hash", "",
		"hash of blob in hexadecimal (base16). Used if you want to sign an artifact stored elsewhere and have the hash")

	cmd.Flags().BoolVarP(&o.SkipConfirmation, "yes", "y", false,
		"skip confirmation prompts for non-destructive operations")

	cmd.Flags().BoolVar(&o.TlogUpload, "tlog-upload", true,
		"whether or not to upload to the tlog")

	cmd.Flags().StringVar(&o.RekorEntryType, "rekor-entry-type", "dsse",
		"specifies the type to be used for a rekor entry upload. Options are intoto or dsse (default). ")

	cmd.Flags().StringVar(&o.TSAServerURL, "timestamp-server-url", "",
		"url to the Timestamp RFC3161 server, default none. Must be the path to the API to request timestamp responses, e.g. https://freetsa.org/tsr")

	cmd.Flags().StringVar(&o.RFC3161TimestampPath, "rfc3161-timestamp-bundle", "",
		"path to an RFC 3161 timestamp bundle FILE")
	_ = cmd.Flags().SetAnnotation("rfc3161-timestamp-bundle", cobra.BashCompFilenameExt, []string{})
}
