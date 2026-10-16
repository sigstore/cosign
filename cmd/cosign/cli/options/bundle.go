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
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

type CommonBundleCreateOptions struct {
	IgnoreTlog bool
	KeyRef     string
	RekorURL   string
	Sk         bool
	Slot       string
}

func (o *CommonBundleCreateOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&o.IgnoreTlog, "ignore-tlog", false,
		"ignore transparency log verification, to be used when an artifact "+
			"signature has not been uploaded to the transparency log.")

	cmd.Flags().StringVar(&o.KeyRef, "key", "",
		"path to the public key file, KMS URI or Kubernetes Secret")
	_ = cmd.MarkFlagFilename("key", publicKeyExts...)

	cmd.Flags().StringVar(&o.RekorURL, "rekor-url", "https://rekor.sigstore.dev",
		"address of rekor STL server")
	_ = cmd.RegisterFlagCompletionFunc("rekor-url", cobra.NoFileCompletions)

	cmd.Flags().BoolVar(&o.Sk, "sk", false,
		"whether to use a hardware security key")

	cmd.Flags().StringVar(&o.Slot, "slot", "signature",
		fmt.Sprintf("security key slot to use for generated key (%s)", strings.Join(securityKeySlots, "|")))
	_ = cmd.RegisterFlagCompletionFunc("slot", cobra.FixedCompletions(securityKeySlots, cobra.ShellCompDirectiveNoFileComp))

	cmd.MarkFlagsMutuallyExclusive("key", "sk")
}

type BundleCreateOptions struct {
	CommonBundleCreateOptions CommonBundleCreateOptions
	Artifact                  string
	AttestationPath           string
	BundlePath                string
	CertificatePath           string
	Out                       string
	RFC3161TimestampPath      string
	SignaturePath             string
}

var _ Interface = (*BundleCreateOptions)(nil)

func (o *BundleCreateOptions) AddFlags(cmd *cobra.Command) {
	o.CommonBundleCreateOptions.AddFlags(cmd)

	cmd.Flags().StringVar(&o.Artifact, "artifact", "",
		"path to artifact FILE")
	// _ = cmd.MarkFlagFilename("artifact") // no typical extensions

	cmd.Flags().StringVar(&o.AttestationPath, "attestation", "",
		"path to attestation FILE")
	// _ = cmd.MarkFlagFilename("attestation") // no typical extensions

	cmd.Flags().StringVar(&o.BundlePath, "bundle", "",
		"path to old format bundle FILE")
	_ = cmd.MarkFlagFilename("bundle", bundleExts...)

	cmd.Flags().StringVar(&o.CertificatePath, "certificate", "",
		"path to the signing certificate, likely from Fulcio.")
	_ = cmd.MarkFlagFilename("certificate", certificateExts...)

	cmd.Flags().StringVar(&o.Out, "out", "", "path to output bundle")
	_ = cmd.MarkFlagFilename("out", bundleExts...)

	cmd.Flags().StringVar(&o.RFC3161TimestampPath, "rfc3161-timestamp", "",
		"path to RFC3161 timestamp FILE")
	// _ = cmd.MarkFlagFilename("rfc3161-timestamp") // no typical extensions

	cmd.Flags().StringVar(&o.SignaturePath, "signature", "",
		"path to base64-encoded signature over attestation in DSSE format")
	_ = cmd.MarkFlagFilename("signature", signatureExts...)

	cmd.MarkFlagsMutuallyExclusive("bundle", "certificate")
	cmd.MarkFlagsMutuallyExclusive("bundle", "signature")
}

type BundleCreateFromContainerOptions struct {
	CommonBundleCreateOptions CommonBundleCreateOptions
	Registry                  RegistryOptions
}

var _ Interface = (*BundleCreateFromContainerOptions)(nil)

func (o *BundleCreateFromContainerOptions) AddFlags(cmd *cobra.Command) {
	o.CommonBundleCreateOptions.AddFlags(cmd)
	o.Registry.AddFlags(cmd)
}

type BundleUpgradeOptions struct {
	Out      string
	RekorURL string
}

var _ Interface = (*BundleUpgradeOptions)(nil)

func (o *BundleUpgradeOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.Out, "out", "", "path to the output upgraded bundle file")
	_ = cmd.MarkFlagFilename("out", bundleExts...)

	cmd.Flags().StringVar(&o.RekorURL, "rekor-url", "https://rekor.sigstore.dev", "URL of the transparency log")
	_ = cmd.RegisterFlagCompletionFunc("rekor-url", cobra.NoFileCompletions)
}
