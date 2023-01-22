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
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/sign/privacy"
	"github.com/sigstore/cosign/v2/internal/pkg/cosign/fulcio/fulcioroots"
	"github.com/sigstore/cosign/v2/internal/ui"
	"github.com/sigstore/cosign/v2/pkg/providers"
	"github.com/sigstore/fulcio/pkg/api"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"github.com/sigstore/sigstore/pkg/signature"
	"go.step.sm/crypto/jose"
	"golang.org/x/term"
)

const (
	flowNormal = "normal"
	flowDevice = "device"
	flowToken  = "token"
)

type oidcConnector interface {
	OIDConnect(string, string, string, string) (*oauthflow.OIDCIDToken, error)
}

type realConnector struct {
	flow oauthflow.TokenGetter
}

func (rf *realConnector) OIDConnect(url, clientID, secret, redirectURL string) (*oauthflow.OIDCIDToken, error) {
	return oauthflow.OIDConnect(url, clientID, secret, redirectURL, rf.flow)
}

func getCertForOauthID(sv signature.SignerVerifier, fc api.LegacyClient, connector oidcConnector, oidcIssuer, oidcClientID, oidcClientSecret, oidcRedirectURL string) (*api.CertificateResponse, error) {
	tok, err := connector.OIDConnect(oidcIssuer, oidcClientID, oidcClientSecret, oidcRedirectURL)
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
	proof, err := sv.SignMessage(strings.NewReader(tok.Subject))
	if err != nil {
		return nil, err
	}

	cr := api.CertificateRequest{
		PublicKey: api.Key{
			Content: pubBytes,
		},
		SignedEmailAddress: proof,
	}

	return fc.SigningCert(cr, tok.RawString)
}

// GetCert returns the PEM-encoded signature of the OIDC identity returned as part of an interactive oauth2 flow plus the PEM-encoded cert chain.
func GetCert(ctx context.Context, sv signature.SignerVerifier, idToken, flow, oidcIssuer, oidcClientID, oidcClientSecret, oidcRedirectURL string, fClient api.LegacyClient) (*api.CertificateResponse, error) {
	c := &realConnector{}
	switch flow {
	case flowDevice:
		c.flow = oauthflow.NewDeviceFlowTokenGetterForIssuer(oidcIssuer)
	case flowNormal:
		c.flow = oauthflow.DefaultIDTokenGetter
	case flowToken:
		c.flow = &oauthflow.StaticTokenGetter{RawToken: idToken}
	default:
		return nil, fmt.Errorf("unsupported oauth flow: %s", flow)
	}

	return getCertForOauthID(sv, fClient, c, oidcIssuer, oidcClientID, oidcClientSecret, oidcRedirectURL)
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

	idToken, err := idToken(ko.IDToken)
	if err != nil {
		return nil, fmt.Errorf("getting id token: %w", err)
	}
	var provider providers.Interface
	// If token is not set in the options, get one from the provders
	if idToken == "" && providers.Enabled(ctx) && !ko.OIDCDisableProviders {
		if ko.OIDCProvider != "" {
			provider, err = providers.ProvideFrom(ctx, ko.OIDCProvider)
			if err != nil {
				return nil, fmt.Errorf("getting provider: %w", err)
			}
			idToken, err = provider.Provide(ctx, "sigstore")
		} else {
			idToken, err = providers.Provide(ctx, "sigstore")
		}
		if err != nil {
			return nil, fmt.Errorf("fetching ambient OIDC credentials: %w", err)
		}
	}

	fmt.Fprintln(os.Stderr, "Retrieving signed certificate...")

	var flow string
	switch {
	case ko.FulcioAuthFlow != "":
		// Caller manually set flow option.
		flow = ko.FulcioAuthFlow
	case idToken != "":
		flow = flowToken
	case !term.IsTerminal(0):
		fmt.Fprintln(os.Stderr, "Non-interactive mode detected, using device flow.")
		flow = flowDevice
	default:
		var statementErr error
		privacy.StatementOnce.Do(func() {
			ui.Infof(ctx, privacy.Statement)
			ui.Infof(ctx, privacy.StatementConfirmation)
			if !ko.SkipConfirmation {
				if err := ui.ConfirmContinue(ctx); err != nil {
					statementErr = err
				}
			}
		})
		if statementErr != nil {
			return nil, statementErr
		}
		flow = flowNormal
	}
	Resp, err := GetCert(ctx, signer, idToken, flow, ko.OIDCIssuer, ko.OIDCClientID, ko.OIDCClientSecret, ko.OIDCRedirectURL, fClient) // TODO, use the chain.
	if err != nil {
		return nil, fmt.Errorf("retrieving cert: %w", err)
	}

	f := &Signer{
		SignerVerifier: signer,
		Cert:           Resp.CertPEM,
		Chain:          Resp.ChainPEM,
		SCT:            Resp.SCT,
	}

	return f, nil
}

func (f *Signer) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
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

// idToken allows users to either pass in an identity token directly
// or a path to an identity token via the --identity-token flag
func idToken(s string) (string, error) {
	// If this is a valid raw token or is empty, just return it
	if _, err := jose.ParseSigned(s); err == nil || s == "" {
		return s, nil
	}

	// Otherwise, if this is a path to a token return the contents
	c, err := os.ReadFile(s)
	return string(c), err
}
