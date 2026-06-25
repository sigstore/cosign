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

	"github.com/sigstore/cosign/v3/internal/pkg/cosign"
)

type CommonVerifyOptions struct {
	IgnoreTlog bool
	MaxWorkers int
	// This is added to CommonVerifyOptions to provide a path to support
	// it for other verify options.
	UseSignedTimestamps bool
	TrustedRootPath     string
}

func (o *CommonVerifyOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&o.UseSignedTimestamps, "use-signed-timestamps", false,
		"verify rfc3161 timestamps")

	cmd.Flags().BoolVar(&o.IgnoreTlog, "insecure-ignore-tlog", false,
		"ignore transparency log verification, to be used when an artifact signature has not been uploaded to the transparency log. Artifacts "+
			"cannot be publicly verified when not included in a log")

	cmd.Flags().IntVar(&o.MaxWorkers, "max-workers", cosign.DefaultMaxWorkers,
		"the amount of maximum workers for parallel executions")
	_ = cmd.RegisterFlagCompletionFunc("max-workers", cobra.NoFileCompletions)

	cmd.Flags().StringVar(&o.TrustedRootPath, "trusted-root", "",
		"Path to a Sigstore TrustedRoot JSON file")
	_ = cmd.MarkFlagFilename("trusted-root", "json")
}

var verifyOutputTypes = []string{"json", "text"} // First one is the default

// VerifyOptions is the top level wrapper for the `verify` command.
type VerifyOptions struct {
	Key         string
	CheckClaims bool
	Output      string
	LocalImage  bool

	CommonVerifyOptions CommonVerifyOptions
	SecurityKey         SecurityKeyOptions
	CertVerify          CertVerifyOptions
	Registry            RegistryOptions

	AnnotationOptions
}

var _ Interface = (*VerifyOptions)(nil)

// AddFlags implements Interface
func (o *VerifyOptions) AddFlags(cmd *cobra.Command) {
	o.SecurityKey.AddFlags(cmd)
	o.CertVerify.AddFlags(cmd)
	o.Registry.AddFlags(cmd)
	o.AnnotationOptions.AddFlags(cmd)
	o.CommonVerifyOptions.AddFlags(cmd)

	cmd.Flags().StringVar(&o.Key, "key", "",
		"path to the public key file, KMS URI or Kubernetes Secret")
	_ = cmd.MarkFlagFilename("key", publicKeyExts...)

	cmd.Flags().BoolVar(&o.CheckClaims, "check-claims", true,
		"whether to check the claims found")

	cmd.Flags().StringVarP(&o.Output, "output", "o", verifyOutputTypes[0],
		"output format for the signing image information ("+strings.Join(verifyOutputTypes, "|")+")")
	_ = cmd.RegisterFlagCompletionFunc("output", cobra.FixedCompletions(verifyOutputTypes, cobra.ShellCompDirectiveNoFileComp))

	cmd.Flags().BoolVar(&o.LocalImage, "local-image", false,
		"whether the specified image is a path to an image saved locally via 'cosign save'")
}

// VerifyAttestationOptions is the top level wrapper for the `verify attestation` command.
type VerifyAttestationOptions struct {
	Key         string
	CheckClaims bool
	Output      string

	CommonVerifyOptions CommonVerifyOptions
	SecurityKey         SecurityKeyOptions
	CertVerify          CertVerifyOptions
	Registry            RegistryOptions
	Predicate           PredicateRemoteOptions
	Policies            []string
	LocalImage          bool
}

var _ Interface = (*VerifyAttestationOptions)(nil)

// AddFlags implements Interface
func (o *VerifyAttestationOptions) AddFlags(cmd *cobra.Command) {
	o.SecurityKey.AddFlags(cmd)
	o.CertVerify.AddFlags(cmd)
	o.Registry.AddFlags(cmd)
	o.Predicate.AddFlags(cmd)
	o.CommonVerifyOptions.AddFlags(cmd)

	cmd.Flags().StringVar(&o.Key, "key", "",
		"path to the public key file, KMS URI or Kubernetes Secret")
	_ = cmd.MarkFlagFilename("key", publicKeyExts...)

	cmd.Flags().BoolVar(&o.CheckClaims, "check-claims", true,
		"whether to check the claims found")

	cmd.Flags().StringSliceVar(&o.Policies, "policy", nil,
		"specify CUE or Rego files with policies to be used for validation")
	_ = cmd.MarkFlagFilename("policy", "cue", "rego")

	cmd.Flags().StringVarP(&o.Output, "output", "o", verifyOutputTypes[0],
		"output format for the signing image information ("+strings.Join(verifyOutputTypes, "|")+")")
	_ = cmd.RegisterFlagCompletionFunc("output", cobra.FixedCompletions(verifyOutputTypes, cobra.ShellCompDirectiveNoFileComp))

	cmd.Flags().BoolVar(&o.LocalImage, "local-image", false,
		"whether the specified image is a path to an image saved locally via 'cosign save'")
}

// VerifyBlobOptions is the top level wrapper for the `verify blob` command.
type VerifyBlobOptions struct {
	Key        string
	BundlePath string

	SecurityKey         SecurityKeyOptions
	CertVerify          CertVerifyOptions
	CommonVerifyOptions CommonVerifyOptions
}

var _ Interface = (*VerifyBlobOptions)(nil)

// AddFlags implements Interface
func (o *VerifyBlobOptions) AddFlags(cmd *cobra.Command) {
	o.SecurityKey.AddFlags(cmd)
	o.CertVerify.AddFlags(cmd)
	o.CommonVerifyOptions.AddFlags(cmd)

	cmd.Flags().StringVar(&o.Key, "key", "",
		"path to the public key file, KMS URI or Kubernetes Secret")
	_ = cmd.MarkFlagFilename("key", publicKeyExts...)

	cmd.Flags().StringVar(&o.BundlePath, "bundle", "",
		"path to bundle FILE")
	_ = cmd.MarkFlagFilename("bundle", bundleExts...)
}

// VerifyDockerfileOptions is the top level wrapper for the `dockerfile verify` command.
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

// VerifyBlobAttestationOptions is the top level wrapper for the `verify-blob-attestation` command.
type VerifyBlobAttestationOptions struct {
	Key        string
	BundlePath string

	PredicateOptions
	CheckClaims bool

	SecurityKey         SecurityKeyOptions
	CertVerify          CertVerifyOptions
	CommonVerifyOptions CommonVerifyOptions

	Digest    string
	DigestAlg string
}

var _ Interface = (*VerifyBlobOptions)(nil)

// AddFlags implements Interface
func (o *VerifyBlobAttestationOptions) AddFlags(cmd *cobra.Command) {
	o.PredicateOptions.AddFlags(cmd)
	o.SecurityKey.AddFlags(cmd)
	o.CertVerify.AddFlags(cmd)
	o.CommonVerifyOptions.AddFlags(cmd)

	cmd.Flags().StringVar(&o.Key, "key", "",
		"path to the public key file, KMS URI or Kubernetes Secret")
	_ = cmd.MarkFlagFilename("key", publicKeyExts...)

	cmd.Flags().StringVar(&o.BundlePath, "bundle", "",
		"path to bundle FILE")
	_ = cmd.MarkFlagFilename("bundle", bundleExts...)

	cmd.Flags().BoolVar(&o.CheckClaims, "check-claims", true,
		"if true, verifies the digest exists in the in-toto subject (using either the provided digest and digest algorithm or the provided blob's sha256 digest). If false, only the DSSE envelope is verified.")

	cmd.Flags().StringVar(&o.Digest, "digest", "",
		"Digest to use for verifying in-toto subject (instead of providing a blob)")
	_ = cmd.RegisterFlagCompletionFunc("digest", cobra.NoFileCompletions)

	cmd.Flags().StringVar(&o.DigestAlg, "digestAlg", "",
		"Digest algorithm to use for verifying in-toto subject (instead of providing a blob)")
	_ = cmd.RegisterFlagCompletionFunc("digestAlg", cobra.FixedCompletions([]string{"sha256", "sha384", "sha512"}, cobra.ShellCompDirectiveNoFileComp))
}
