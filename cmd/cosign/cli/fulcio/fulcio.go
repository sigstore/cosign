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

package fulcio

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/internal/auth"
	"github.com/sigstore/cosign/v2/internal/pkg/cosign/fulcio/fulcioroots"
	"github.com/sigstore/fulcio/pkg/api"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

// GetCert returns the PEM-encoded signature of the OIDC identity returned as part of an interactive oauth2 flow plus the PEM-encoded cert chain.
func GetCert(_ context.Context, sv signature.SignerVerifier, idToken, flow, oidcIssuer, oidcClientID, oidcClientSecret, oidcRedirectURL string, fClient api.LegacyClient) (*api.CertificateResponse, error) {
	sub, tok, err := auth.AuthenticateCaller(flow, idToken, oidcIssuer, oidcClientID, oidcClientSecret, oidcRedirectURL)
	if err != nil {
		return nil, err
	}
	publicKey, err := sv.PublicKey()
	if err != nil {
		return nil, err
	}
	pubBytes, err := cryptoutils.MarshalPublicKeyToPEM(publicKey)
	if err != nil {
		return nil, err
	}
	// Sign the email address as part of the request
	proof, err := sv.SignMessage(strings.NewReader(sub))
	if err != nil {
		return nil, err
	}

	cr := api.CertificateRequest{
		PublicKey: api.Key{
			Content: pubBytes,
		},
		SignedEmailAddress: proof,
	}

	fmt.Fprintln(os.Stderr, "Retrieving signed certificate...")

	return fClient.SigningCert(cr, tok)
}

type Signer struct {
	Cert  []byte
	Chain []byte
	SCT   []byte
	signature.SignerVerifier
}

func NewSigner(ctx context.Context, ko options.KeyOpts, signer signature.SignerVerifier) (*Signer, error) {
	fClient, err := NewClient(ko.FulcioURL)
	if err != nil {
		return nil, fmt.Errorf("creating Fulcio client: %w", err)
	}

	idToken, err := auth.ReadIDToken(ctx, ko.IDToken, ko.OIDCDisableProviders, ko.OIDCProvider)
	if err != nil {
		return nil, fmt.Errorf("reading id token: %w", err)
	}

	flow, err := auth.GetOAuthFlow(ctx, ko.FulcioAuthFlow, idToken, ko.SkipConfirmation)
	if err != nil {
		return nil, fmt.Errorf("setting auth flow: %w", err)
	}

	resp, err := GetCert(ctx, signer, idToken, flow, ko.OIDCIssuer, ko.OIDCClientID, ko.OIDCClientSecret, ko.OIDCRedirectURL, fClient)
	if err != nil {
		return nil, fmt.Errorf("retrieving cert: %w", err)
	}

	f := &Signer{
		SignerVerifier: signer,
		Cert:           resp.CertPEM,
		Chain:          resp.ChainPEM,
		SCT:            resp.SCT,
	}

	return f, nil
}

func (f *Signer) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) { //nolint: revive
	return f.SignerVerifier.PublicKey()
}

var _ signature.Signer = &Signer{}

func GetRoots() (*x509.CertPool, error) {
	return fulcioroots.Get()
}

func GetIntermediates() (*x509.CertPool, error) {
	return fulcioroots.GetIntermediates()
}

func NewClient(fulcioURL string) (api.LegacyClient, error) {
	fulcioServer, err := url.Parse(fulcioURL)
	if err != nil {
		return nil, err
	}
	fClient := api.NewClient(fulcioServer, api.WithUserAgent(options.UserAgent()))
	return fClient, nil
}
