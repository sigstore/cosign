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
	fulcioclient "github.com/sigstore/fulcio/pkg/client"
)

// SignOptions is the top level wrapper for the sign command.
type SignOptions struct {
	Key              string
	Cert             string
	Upload           bool
	SecurityKey      bool
	SecurityKeySlot  string
	PayloadPath      string
	Force            bool
	Recursive        bool
	FulcioURL        string
	RektorURL        string
	IdentityToken    string
	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string
	Attachment       string

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

func AddSignOptions(cmd *cobra.Command, o *SignOptions) {
	cmd.Flags().StringVar(&o.Key, "key", "",
		"path to the private key file, KMS URI or Kubernetes Secret")

	cmd.Flags().StringVar(&o.Cert, "cert", "",
		"path to the x509 certificate to include in the Signature")

	cmd.Flags().BoolVar(&o.Upload, "upload", true,
		"whether to upload the signature")

	cmd.Flags().BoolVar(&o.SecurityKey, "sk", false,
		"whether to use a hardware security key")

	cmd.Flags().StringVar(&o.SecurityKeySlot, "slot", "",
		"security key slot to use for generated key (default: signature) (authentication|signature|card-authentication|key-management)")

	cmd.Flags().StringVar(&o.PayloadPath, "payload", "",
		"path to a payload file to use rather than generating one")

	cmd.Flags().BoolVarP(&o.Force, "force", "f", false,
		"skip warnings and confirmations")

	cmd.Flags().BoolVarP(&o.Recursive, "recursive", "r", false,
		"if a multi-arch image is specified, additionally sign each discrete image")

	cmd.Flags().StringVar(&o.OIDCIssuer, "attachment", "",
		"related image attachment to sign (sbom), default none")

	cmd.Flags().StringSliceVarP(&o.Annotations, "annotations", "a", nil,
		"extra key=value pairs to sign")

	cmd.Flags().BoolVar(&o.RegistryOpts.AllowInsecure, "allow-insecure-registry", false,
		"whether to allow insecure connections to registries. Don't use this for anything but testing")

	// TODO: an interesting idea? This hides the flags that are experimental
	// unless experimental is enabled.
	if EnableExperimental() {
		cmd.Flags().StringVar(&o.FulcioURL, "fulcio-url", fulcioclient.SigstorePublicServerURL,
			"[EXPERIMENTAL] address of sigstore PKI server")

		cmd.Flags().StringVar(&o.RektorURL, "rekor-url", "https://rekor.sigstore.dev",
			"[EXPERIMENTAL] address of rekor STL server")

		cmd.Flags().StringVar(&o.IdentityToken, "identity-token", "",
			"[EXPERIMENTAL] identity token to use for certificate from fulcio")

		cmd.Flags().StringVar(&o.OIDCIssuer, "oidc-issuer", "https://oauth2.sigstore.dev/auth",
			"[EXPERIMENTAL] OIDC provider to be used to issue ID token")

		cmd.Flags().StringVar(&o.OIDCClientID, "oidc-client-id", "sigstore",
			"[EXPERIMENTAL] OIDC client ID for application")

		cmd.Flags().StringVar(&o.OIDCClientSecret, "oidc-client-secret", "",
			"[EXPERIMENTAL] OIDC client secret for application")
	}
}
