//
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
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/sigstore/pkg/signature"
)

type KeyOpts struct {
	Sk                   bool
	Slot                 string
	KeyRef               string
	FulcioURL            string
	RekorURL             string
	IDToken              string
	PassFunc             cosign.PassFunc
	OIDCIssuer           string
	OIDCClientID         string
	OIDCClientSecret     string
	OIDCRedirectURL      string
	OIDCDisableProviders bool   // Disable OIDC credential providers in keyless signer
	OIDCProvider         string // Specify which OIDC credential provider to use for keyless signer
	BundlePath           string
	NewBundleFormat      bool
	SkipConfirmation     bool
	TSAClientCACert      string
	TSAClientCert        string
	TSAClientKey         string
	TSAServerName        string // expected SAN field in the TSA server's certificate - https://pkg.go.dev/crypto/tls#Config.ServerName
	TSAServerURL         string
	RFC3161TimestampPath string
	TSACertChainPath     string
	// IssueCertificate controls whether to issue a certificate when a key is
	// provided.
	IssueCertificateForExistingKey bool

	// FulcioAuthFlow is the auth flow to use when authenticating against
	// Fulcio. See https://pkg.go.dev/github.com/sigstore/cosign/v2/cmd/cosign/cli/fulcio#pkg-constants
	// for valid values.
	FulcioAuthFlow string

	// Modeled after InsecureSkipVerify in tls.Config, this disables
	// verifying the SCT.
	InsecureSkipFulcioVerify bool

	// DefaultLoadOptions may be set to control the behaviour of
	// `LoadDefaultSigner/Verifier` family of functions. Some public/private key
	// types have ambiguities with regards to the signing algorithm to use (e.g.
	// RSA can be RSASSA-PSS or RSASSA-PKCS1v15). This is a way to control that.
	//
	// By default, Ed25519ph is used for ed25519 keys and RSA-PKCS1v15 is used
	// for RSA keys.
	DefaultLoadOptions *[]signature.LoadOption

	// SigningAlgorithm is the AlgorithmDetails string representation used to
	// sign/hash the payload.
	SigningAlgorithm string
}
