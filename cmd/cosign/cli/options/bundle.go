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

type BundleCreateOptions struct {
	Artifact             string
	AttestationPath      string
	BundlePath           string
	CertificatePath      string
	IgnoreTlog           bool
	KeyRef               string
	Out                  string
	RekorURL             string
	RFC3161TimestampPath string
	SignaturePath        string
	Sk                   bool
	Slot                 string
}

var _ Interface = (*BundleCreateOptions)(nil)

func (o *BundleCreateOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.Artifact, "artifact", "",
		"path to artifact FILE")

	cmd.Flags().StringVar(&o.AttestationPath, "attestation", "",
		"path to attestation FILE")

	cmd.Flags().StringVar(&o.BundlePath, "bundle", "",
		"path to old format bundle FILE")

	cmd.Flags().StringVar(&o.CertificatePath, "certificate", "",
		"path to the signing certificate, likely from Fulco.")

	cmd.Flags().BoolVar(&o.IgnoreTlog, "ignore-tlog", false,
		"ignore transparency log verification, to be used when an artifact "+
			"signature has not been uploaded to the transparency log.")

	cmd.Flags().StringVar(&o.KeyRef, "key", "",
		"path to the public key file, KMS URI or Kubernetes Secret")

	cmd.Flags().StringVar(&o.Out, "out", "", "path to output bundle")

	cmd.Flags().StringVar(&o.RekorURL, "rekor-url", "https://rekor.sigstore.dev",
		"address of rekor STL server")

	cmd.Flags().StringVar(&o.RFC3161TimestampPath, "rfc3161-timestamp", "",
		"path to RFC3161 timestamp FILE")

	cmd.Flags().StringVar(&o.SignaturePath, "signature", "",
		"path to base64-encoded signature over attestation in DSSE format")

	cmd.Flags().BoolVar(&o.Sk, "sk", false,
		"whether to use a hardware security key")

	cmd.Flags().StringVar(&o.Slot, "slot", "",
		"security key slot to use for generated key (default: signature) "+
			"(authentication|signature|card-authentication|key-management)")

	cmd.MarkFlagsMutuallyExclusive("bundle", "certificate")
	cmd.MarkFlagsMutuallyExclusive("bundle", "signature")
}
