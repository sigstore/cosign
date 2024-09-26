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
	CAIntermediates  string
	CARoots          string
	CertChain        string
	CtfeKeyPath      string
	RekorKeyPath     string
	Out              string
	TSACertChainPath string
}

var _ Interface = (*TrustedRootCreateOptions)(nil)

func (o *TrustedRootCreateOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.CAIntermediates, "ca-intermediates", "",
		"path to a file of intermediate CA certificates in PEM format which will be needed "+
			"when building the certificate chains for the signing certificate. "+
			"The flag is optional and must be used together with --ca-roots, conflicts with "+
			"--certificate-chain.")
	_ = cmd.Flags().SetAnnotation("ca-intermediates", cobra.BashCompFilenameExt, []string{"cert"})

	cmd.Flags().StringVar(&o.CARoots, "ca-roots", "",
		"path to a bundle file of CA certificates in PEM format which will be needed "+
			"when building the certificate chains for the signing certificate. Conflicts with --certificate-chain.")
	_ = cmd.Flags().SetAnnotation("ca-roots", cobra.BashCompFilenameExt, []string{"cert"})

	cmd.Flags().StringVar(&o.CertChain, "certificate-chain", "",
		"path to a list of CA certificates in PEM format which will be needed "+
			"when building the certificate chain for the signing certificate. "+
			"Must start with the parent intermediate CA certificate of the "+
			"signing certificate and end with the root certificate. Conflicts with --ca-roots and --ca-intermediates.")
	_ = cmd.Flags().SetAnnotation("certificate-chain", cobra.BashCompFilenameExt, []string{"cert"})

	cmd.MarkFlagsMutuallyExclusive("ca-roots", "certificate-chain")
	cmd.MarkFlagsMutuallyExclusive("ca-intermediates", "certificate-chain")

	cmd.Flags().StringVar(&o.CtfeKeyPath, "ctfe-key", "",
		"path to a PEM-encoded public key used by certificate authority for "+
			"certificate transparency log.")

	cmd.Flags().StringVar(&o.RekorKeyPath, "rekor-key", "",
		"path to a PEM-encoded public key used by transparency log like Rekor.")

	cmd.Flags().StringVar(&o.Out, "out", "",
		"path to output trusted root")

	cmd.Flags().StringVar(&o.TSACertChainPath, "timestamp-certificate-chain", "",
		"path to PEM-encoded certificate chain file for the RFC3161 timestamp authority. Must contain the root CA certificate. "+
			"Optionally may contain intermediate CA certificates")
}
