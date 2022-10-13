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
	"time"

	"github.com/spf13/cobra"
)

// AttestOptions is the top level wrapper for the attest command.
type AttestBlobOptions struct {
	Key               string
	Cert              string
	CertChain         string
	NoUpload          bool
	Force             bool
	Recursive         bool
	Replace           bool
	Timeout           time.Duration
	Hash              string
	OutputSignature   string
	OutputAttestation string

	Rekor       RekorOptions
	Fulcio      FulcioOptions
	OIDC        OIDCOptions
	SecurityKey SecurityKeyOptions
	Predicate   PredicateLocalOptions
}

var _ Interface = (*AttestOptions)(nil)

// AddFlags implements Interface
func (o *AttestBlobOptions) AddFlags(cmd *cobra.Command) {
	o.SecurityKey.AddFlags(cmd)
	o.Predicate.AddFlags(cmd)
	o.Fulcio.AddFlags(cmd)
	o.OIDC.AddFlags(cmd)
	o.Rekor.AddFlags(cmd)

	cmd.Flags().StringVar(&o.Key, "key", "",
		"path to the private key file, KMS URI or Kubernetes Secret")

	cmd.Flags().StringVar(&o.Cert, "cert", "",
		"path to the x509 certificate to include in the Signature")

	cmd.Flags().StringVar(&o.OutputSignature, "output-signature", "",
		"write the signature to FILE")
	_ = cmd.Flags().SetAnnotation("output-signature", cobra.BashCompFilenameExt, []string{})

	cmd.Flags().StringVar(&o.OutputAttestation, "output-attestation", "",
		"write the attestation to FILE")

	cmd.Flags().StringVar(&o.CertChain, "cert-chain", "",
		"path to a list of CA X.509 certificates in PEM format which will be needed "+
			"when building the certificate chain for the signing certificate. "+
			"Must start with the parent intermediate CA certificate of the "+
			"signing certificate and end with the root certificate. Included in the OCI Signature")

	cmd.Flags().BoolVar(&o.NoUpload, "no-upload", false,
		"do not upload the generated attestation")

	cmd.Flags().BoolVarP(&o.Force, "force", "f", false,
		"skip warnings and confirmations")

	cmd.Flags().BoolVarP(&o.Replace, "replace", "", false,
		"")

	cmd.Flags().DurationVar(&o.Timeout, "timeout", time.Second*30,
		"HTTP Timeout defaults to 30 seconds")

	cmd.Flags().StringVar(&o.Hash, "hash", "",
		"hash of blob in hexadecimal (base16). Used if you want to sign an artifact stored elsewhere and have the hash")
}
