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
	CertChain        []string
	CtfeKeyPath      []string
	CtfeStartTime    []string
	Out              string
	RekorKeyPath     []string
	RekorStartTime   []string
	TSACertChainPath []string
}

var _ Interface = (*TrustedRootCreateOptions)(nil)

func (o *TrustedRootCreateOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringArrayVar(&o.CertChain, "certificate-chain", nil,
		"path to a list of CA certificates in PEM format which will be needed "+
			"when building the certificate chain for the signing certificate. "+
			"Must start with the parent intermediate CA certificate of the "+
			"signing certificate and end with the root certificate.")
	_ = cmd.MarkFlagFilename("certificate-chain", certificateExts...)

	cmd.Flags().StringArrayVar(&o.CtfeKeyPath, "ctfe-key", nil,
		"path to a PEM-encoded public key used by certificate authority for "+
			"certificate transparency log.")
	_ = cmd.MarkFlagFilename("ctfe-key", publicKeyExts...)

	cmd.Flags().StringArrayVar(&o.CtfeStartTime, "ctfe-start-time", nil,
		"RFC 3339 string describing validity start time for key use by "+
			"certificate transparency log.")

	cmd.Flags().StringVar(&o.Out, "out", "", "path to output trusted root")
	// _ = cmd.MarkFlagFilename("output") // no typical extensions

	cmd.Flags().StringArrayVar(&o.RekorKeyPath, "rekor-key", nil,
		"path to a PEM-encoded public key used by transparency log like Rekor.")
	_ = cmd.MarkFlagFilename("rekor-key", publicKeyExts...)

	cmd.Flags().StringArrayVar(&o.RekorStartTime, "rekor-start-time", nil,
		"RFC 3339 string describing validity start time for key use by "+
			"transparency log like Rekor.")

	cmd.Flags().StringArrayVar(&o.TSACertChainPath, "timestamp-certificate-chain", nil,
		"path to PEM-encoded certificate chain file for the RFC3161 timestamp authority. Must contain the root CA certificate. "+
			"Optionally may contain intermediate CA certificates")
	_ = cmd.MarkFlagFilename("timestamp-certificate-chain", certificateExts...)
}
