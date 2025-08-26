//
// Copyright 2024 The Sigstore Authors.
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

type TrustedRootCreateOptions struct {
	Fulcio []string
	CTFE   []string
	TSA    []string
	Rekor  []string

	CertChain        []string
	FulcioURI        []string
	CtfeKeyPath      []string
	CtfeStartTime    []string
	CtfeEndTime      []string
	CtfeURL          []string
	Out              string
	RekorKeyPath     []string
	RekorStartTime   []string
	RekorEndTime     []string
	RekorURL         []string
	TSACertChainPath []string
	TSAURI           []string
}

var _ Interface = (*TrustedRootCreateOptions)(nil)

func (o *TrustedRootCreateOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringArrayVar(&o.Fulcio, "fulcio", nil,
		"fulcio service specification, as a comma-separated key-value list.\nRequired keys: url, certificate-chain (path to PEM-encoded certificate chain). Optional keys: start-time, end-time.")
	cmd.Flags().StringArrayVar(&o.CTFE, "ctfe", nil,
		"ctfe service specification, as a comma-separated key-value list.\nRequired keys: url, public-key (path to PEM-encoded public key), start-time. Optional keys: end-time.")
	cmd.Flags().StringArrayVar(&o.TSA, "tsa", nil,
		"timestamping authority specification, as a comma-separated key-value list.\nRequired keys: url, certificate-chain (path to PEM-encoded certificate chain). Optional keys: start-time, end-time.")
	cmd.Flags().StringArrayVar(&o.Rekor, "rekor", nil,
		"rekor service specification, as a comma-separated key-value list.\nRequired keys: url, public-key (path to PEM-encoded public key), start-time. Optional keys: end-time, origin.")

	cmd.Flags().StringArrayVar(&o.CertChain, "certificate-chain", nil,
		"path to a list of CA certificates in PEM format which will be needed "+
			"when building the certificate chain for the signing certificate. "+
			"Must start with the parent intermediate CA certificate of the "+
			"signing certificate and end with the root certificate.")
	_ = cmd.MarkFlagFilename("certificate-chain", certificateExts...)
	_ = cmd.Flags().MarkDeprecated("certificate-chain", "use --fulcio instead")

	cmd.Flags().StringArrayVar(&o.FulcioURI, "fulcio-uri", nil,
		"URI of the Fulcio server issuing certificates.")
	_ = cmd.Flags().MarkDeprecated("fulcio-uri", "use --fulcio instead")

	cmd.Flags().StringArrayVar(&o.CtfeKeyPath, "ctfe-key", nil,
		"path to a PEM-encoded public key used by certificate authority for "+
			"certificate transparency log.")
	_ = cmd.MarkFlagFilename("ctfe-key", publicKeyExts...)
	_ = cmd.Flags().MarkDeprecated("ctfe-key", "use --ctfe instead")

	cmd.Flags().StringArrayVar(&o.CtfeStartTime, "ctfe-start-time", nil,
		"RFC 3339 string describing validity start time for key use by "+
			"certificate transparency log.")
	_ = cmd.Flags().MarkDeprecated("ctfe-start-time", "use --ctfe instead")

	cmd.Flags().StringArrayVar(&o.CtfeEndTime, "ctfe-end-time", nil,
		"RFC 3339 string describing validity end time for key use by "+
			"certificate transparency log.")
	_ = cmd.Flags().MarkDeprecated("ctfe-end-time", "use --ctfe instead")

	cmd.Flags().StringArrayVar(&o.CtfeURL, "ctfe-url", nil,
		"URL of the certificate transparency log.")
	_ = cmd.Flags().MarkDeprecated("ctfe-url", "use --ctfe instead")

	cmd.Flags().StringVar(&o.Out, "out", "", "path to output trusted root")
	// _ = cmd.MarkFlagFilename("output") // no typical extensions

	cmd.Flags().StringArrayVar(&o.RekorKeyPath, "rekor-key", nil,
		"path to a PEM-encoded public key used by transparency log like Rekor. "+
			"For Rekor V2, append the Rekor server name with ',', e.g. "+
			"'--rekor-key=/path/to/key.pub,rekor.example.test'.")
	_ = cmd.MarkFlagFilename("rekor-key", publicKeyExts...)
	_ = cmd.Flags().MarkDeprecated("rekor-key", "use --rekor instead")

	cmd.Flags().StringArrayVar(&o.RekorStartTime, "rekor-start-time", nil,
		"RFC 3339 string describing validity start time for key use by "+
			"transparency log like Rekor.")
	_ = cmd.Flags().MarkDeprecated("rekor-start-time", "use --rekor instead")

	cmd.Flags().StringArrayVar(&o.RekorEndTime, "rekor-end-time", nil,
		"RFC 3339 string describing validity end time for key use by "+
			"transparency log like Rekor.")
	_ = cmd.Flags().MarkDeprecated("rekor-end-time", "use --rekor instead")

	cmd.Flags().StringArrayVar(&o.RekorURL, "rekor-url", nil,
		"URL of the transparency log.")
	_ = cmd.Flags().MarkDeprecated("rekor-url", "use --rekor instead")

	cmd.Flags().StringArrayVar(&o.TSACertChainPath, "timestamp-certificate-chain", nil,
		"path to PEM-encoded certificate chain file for the RFC3161 timestamp authority. Must contain the root CA certificate. "+
			"Optionally may contain intermediate CA certificates")
	_ = cmd.MarkFlagFilename("timestamp-certificate-chain", certificateExts...)
	_ = cmd.Flags().MarkDeprecated("timestamp-certificate-chain", "use --tsa instead")

	cmd.Flags().StringArrayVar(&o.TSAURI, "timestamp-uri", nil,
		"URI of the timestamp authority server.")
	_ = cmd.Flags().MarkDeprecated("timestamp-uri", "use --tsa instead")
}
