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

// SignOptions is the top level wrapper for the sign command.
type SignOptions struct {
	Key         string
	Cert        string
	Upload      bool
	SecurityKey SecurityKeyOptions
	PayloadPath string
	Force       bool
	Recursive   bool

	Fulcio FulcioOptions
	Rektor RekorOptions

	OIDC       OIDCOptions
	Attachment string

	AnnotationOptions
	Registry RegistryOptions
}

var _ Interface = (*SignOptions)(nil)

// AddFlags implements Interface
func (o *SignOptions) AddFlags(cmd *cobra.Command) {
	o.Rektor.AddFlags(cmd)
	o.Fulcio.AddFlags(cmd)
	o.OIDC.AddFlags(cmd)
	o.SecurityKey.AddFlags(cmd)
	o.AnnotationOptions.AddFlags(cmd)
	o.Registry.AddFlags(cmd)

	cmd.Flags().StringVar(&o.Key, "key", "",
		"path to the private key file, KMS URI or Kubernetes Secret")

	cmd.Flags().StringVar(&o.Cert, "cert", "",
		"path to the x509 certificate to include in the Signature")

	cmd.Flags().BoolVar(&o.Upload, "upload", true,
		"whether to upload the signature")

	cmd.Flags().StringVar(&o.PayloadPath, "payload", "",
		"path to a payload file to use rather than generating one")

	cmd.Flags().BoolVarP(&o.Force, "force", "f", false,
		"skip warnings and confirmations")

	cmd.Flags().BoolVarP(&o.Recursive, "recursive", "r", false,
		"if a multi-arch image is specified, additionally sign each discrete image")

	cmd.Flags().StringVar(&o.Attachment, "attachment", "",
		"related image attachment to sign (sbom), default none")
<<<<<<< HEAD

	cmd.Flags().BoolVar(&o.RegistryOpts.AllowInsecure, "allow-insecure-registry", false,
		"whether to allow insecure connections to registries. Don't use this for anything but testing")

	cmd.Flags().StringVar(&o.RegistryOpts.TagPrefix, "signature-prefix", "",
		"custom prefix to use for signature tag")

	cmd.Flags().StringVar(&o.RegistryOpts.TagSuffix, "signature-suffix", "",
		"custom suffix to use for signature tag")
=======
>>>>>>> 874644e (Migrate copy and clean to cobra. Add RegistryOptions to match the style of other flags. Move init. Move triangulate (#806))
}
