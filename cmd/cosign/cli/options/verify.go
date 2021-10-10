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

// VerifyOptions is the top level wrapper for the `verify` command.
type VerifyOptions struct {
	Key         string
	CertEmail   string // TODO: merge into fulcio option as read mode?
	CheckClaims bool
	Attachment  string
	Output      string

	SecurityKey SecurityKeyOptions
	Rekor       RekorOptions
	// TODO: this seems like it should have the Fulcio options.
	Registry RegistryOptions
	AnnotationOptions
}

var _ Interface = (*VerifyOptions)(nil)

// AddFlags implements Interface
func (o *VerifyOptions) AddFlags(cmd *cobra.Command) {
	o.SecurityKey.AddFlags(cmd)
	o.Rekor.AddFlags(cmd)
	o.Registry.AddFlags(cmd)
	o.AnnotationOptions.AddFlags(cmd)

	cmd.Flags().StringVar(&o.Key, "key", "",
		"path to the private key file, KMS URI or Kubernetes Secret")

	cmd.Flags().StringVar(&o.CertEmail, "cert-email", "",
		"the email expected in a valid fulcio cert")

	cmd.Flags().BoolVar(&o.CheckClaims, "check-claims", true,
		"whether to check the claims found")

	cmd.Flags().StringVar(&o.Attachment, "attachment", "",
		"related image attachment to sign (sbom), default none")

	cmd.Flags().StringVarP(&o.Output, "output", "o", "json",
		"output format for the signing image information (json|text)")
}

// VerifyAttestationOptions is the top level wrapper for the `verify attestation` command.
type VerifyAttestationOptions struct {
	Key         string
	CheckClaims bool
	Output      string

	SecurityKey SecurityKeyOptions
	Rekor       RekorOptions
	Fulcio      FulcioOptions // TODO: the original command did not use id token, mistake?
	Registry    RegistryOptions
	Predicate   PredicateRemoteOptions
	Policies    []string
}

var _ Interface = (*VerifyAttestationOptions)(nil)

// AddFlags implements Interface
func (o *VerifyAttestationOptions) AddFlags(cmd *cobra.Command) {
	o.SecurityKey.AddFlags(cmd)
	o.Rekor.AddFlags(cmd)
	o.Fulcio.AddFlags(cmd)
	o.Registry.AddFlags(cmd)
	o.Predicate.AddFlags(cmd)

	cmd.Flags().StringVar(&o.Key, "key", "",
		"path to the private key file, KMS URI or Kubernetes Secret")

	cmd.Flags().BoolVar(&o.CheckClaims, "check-claims", true,
		"whether to check the claims found")

	cmd.Flags().StringSliceVar(&o.Policies, "policy", nil,
		"specify CUE or Rego files will be using for validation")

	cmd.Flags().StringVarP(&o.Output, "output", "o", "json",
		"output format for the signing image information (json|text)")
}

// VerifyBlobOptions is the top level wrapper for the `verify blob` command.
type VerifyBlobOptions struct {
	Key       string
	Cert      string
	Signature string

	SecurityKey SecurityKeyOptions
	Rekor       RekorOptions
	Registry    RegistryOptions
}

var _ Interface = (*VerifyBlobOptions)(nil)

// AddFlags implements Interface
func (o *VerifyBlobOptions) AddFlags(cmd *cobra.Command) {
	o.SecurityKey.AddFlags(cmd)
	o.Rekor.AddFlags(cmd)
	o.Registry.AddFlags(cmd)

	cmd.Flags().StringVar(&o.Key, "key", "",
		"path to the private key file, KMS URI or Kubernetes Secret")

	cmd.Flags().StringVar(&o.Cert, "cert", "",
		"path to the public certificate")

	cmd.Flags().StringVar(&o.Signature, "signature", "",
		"signature content or path or remote URL")
}

// VerifyBlobOptions is the top level wrapper for the `verify blob` command.
type VerifyDockerfileOptions struct {
	VerifyOptions
	BaseImageOnly bool
}

var _ Interface = (*VerifyDockerfileOptions)(nil)

// AddFlags implements Interface
func (o *VerifyDockerfileOptions) AddFlags(cmd *cobra.Command) {
	o.VerifyOptions.AddFlags(cmd)

	cmd.Flags().BoolVar(&o.BaseImageOnly, "base-image-only", false,
		"only verify the base image (the last FROM image in the Dockerfile)")
}
