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
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	sigs "github.com/sigstore/cosign/pkg/signature"
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

	Annotations  []string
	RegistryOpts RegistryOpts
}

func (s *SignOptions) AnnotationsMap() (sigs.AnnotationsMap, error) {
	ann := sigs.AnnotationsMap{}
	for _, a := range s.Annotations {
		kv := strings.Split(a, "=")
		if len(kv) != 2 {
			return ann, fmt.Errorf("unable to parse annotation: %s", a)
		}
		ann.Annotations[kv[0]] = kv[1]
	}
	return ann, nil
}

// AddSignOptions adds the sign command options to cmd.
func AddSignOptions(cmd *cobra.Command, o *SignOptions) {
	cmd.Flags().StringVar(&o.Key, "key", "",
		"path to the private key file, KMS URI or Kubernetes Secret")

	cmd.Flags().StringVar(&o.Cert, "cert", "",
		"path to the x509 certificate to include in the Signature")

	cmd.Flags().BoolVar(&o.Upload, "upload", true,
		"whether to upload the signature")

	AddSecurityKeyOptions(cmd, &o.SecurityKey)

	cmd.Flags().StringVar(&o.PayloadPath, "payload", "",
		"path to a payload file to use rather than generating one")

	cmd.Flags().BoolVarP(&o.Force, "force", "f", false,
		"skip warnings and confirmations")

	cmd.Flags().BoolVarP(&o.Recursive, "recursive", "r", false,
		"if a multi-arch image is specified, additionally sign each discrete image")

	cmd.Flags().StringVar(&o.Attachment, "attachment", "",
		"related image attachment to sign (sbom), default none")

	cmd.Flags().StringSliceVarP(&o.Annotations, "annotations", "a", nil,
		"extra key=value pairs to sign")

	cmd.Flags().BoolVar(&o.RegistryOpts.AllowInsecure, "allow-insecure-registry", false,
		"whether to allow insecure connections to registries. Don't use this for anything but testing")

	AddRekorOptions(cmd, &o.Rektor)

	AddFulcioOptions(cmd, &o.Fulcio)

	AddOIDCOptions(cmd, &o.OIDC)
}
