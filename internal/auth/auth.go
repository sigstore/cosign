// Copyright 2025 The Sigstore Authors.
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

package auth

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/sign/privacy"
	"github.com/sigstore/cosign/v2/internal/ui"
	"github.com/sigstore/cosign/v2/pkg/providers"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"golang.org/x/term"
)

const (
	flowNormal            = "normal"
	flowDevice            = "device"
	flowToken             = "token"
	flowClientCredentials = "client_credentials"
)

var SigstoreOIDCIssuerAPIVersions = []uint32{1}

type IDTokenConfig struct {
	TokenOrPath      string
	DisableProviders bool
	Provider         string
	AuthFlow         string
	SkipConfirm      bool
	OIDCServices     []root.Service
	ClientID         string
	ClientSecret     string
	RedirectURL      string
}

// RetrieveIDToken returns an ID token from one of the following sources:
// * Flag value
// * File, path provided by flag
// * Provider, e.g. a well-known location of a token for an environment like K8s or CI/CD
// * OpenID Connect authentication protocol
func RetrieveIDToken(ctx context.Context, c IDTokenConfig) (string, error) {
	idToken, err := ReadIDToken(ctx, c.TokenOrPath, c.DisableProviders, c.Provider)
	if err != nil {
		return "", fmt.Errorf("reading ID token: %w", err)
	}
	if idToken != "" {
		return idToken, nil
	}
	flow, err := GetOAuthFlow(ctx, c.AuthFlow, idToken, c.SkipConfirm)
	if err != nil {
		return "", fmt.Errorf("setting auth flow: %w", err)
	}
	oidcIssuerSvc, err := root.SelectService(c.OIDCServices, SigstoreOIDCIssuerAPIVersions, time.Now())
	if err != nil {
		return "", fmt.Errorf("selecting OIDC issuer: %w", err)
	}
	_, idToken, err = AuthenticateCaller(flow, idToken, oidcIssuerSvc.URL, c.ClientID, c.ClientSecret, c.RedirectURL)
	if err != nil {
		return "", fmt.Errorf("authenticating caller: %w", err)
	}
	return idToken, err
}

// ReadIDToken returns an OpenID Connect token from either a file or a well-known location from an identity provider
func ReadIDToken(ctx context.Context, tokOrPath string, disableProviders bool, oidcProvider string) (string, error) {
	idToken, err := idToken(tokOrPath)
	if err != nil {
		return "", fmt.Errorf("getting id token: %w", err)
	}
	var provider providers.Interface
	// If token is not set in the options, get one from the provders
	if idToken == "" && providers.Enabled(ctx) && !disableProviders {
		if oidcProvider != "" {
			provider, err = providers.ProvideFrom(ctx, oidcProvider)
			if err != nil {
				return "", fmt.Errorf("getting provider: %w", err)
			}
			idToken, err = provider.Provide(ctx, "sigstore")
		} else {
			idToken, err = providers.Provide(ctx, "sigstore")
		}
		if err != nil {
			return "", fmt.Errorf("fetching ambient OIDC credentials: %w", err)
		}
	}
	return idToken, nil
}

// GetOAuthFlow returns authentication flow that the client will initiate
func GetOAuthFlow(ctx context.Context, authFlow, idToken string, skipConfirm bool) (string, error) {
	var flow string
	switch {
	case authFlow != "":
		// Caller manually set flow option.
		flow = authFlow
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
			if !skipConfirm {
				if err := ui.ConfirmContinue(ctx); err != nil {
					statementErr = err
				}
			}
		})
		if statementErr != nil {
			return "", statementErr
		}
		flow = flowNormal
	}
	return flow, nil
}

// AuthenticateCaller performs an OpenID Connect authentication to exchange credentials for an identity token
func AuthenticateCaller(flow, idToken, oidcIssuer, oidcClientID, oidcClientSecret, oidcRedirectURL string) (string, string, error) {
	var tokenGetter oauthflow.TokenGetter
	switch flow {
	case flowClientCredentials:
		tokenGetter = oauthflow.NewClientCredentialsFlow(oidcIssuer)
	case flowDevice:
		tokenGetter = oauthflow.NewDeviceFlowTokenGetterForIssuer(oidcIssuer)
	case flowNormal:
		tokenGetter = oauthflow.DefaultIDTokenGetter
	case flowToken:
		tokenGetter = &oauthflow.StaticTokenGetter{RawToken: idToken}
	default:
		return "", "", fmt.Errorf("unsupported oauth flow: %s", flow)
	}

	tok, err := oauthflow.OIDConnect(oidcIssuer, oidcClientID, oidcClientSecret, oidcRedirectURL, tokenGetter)
	if err != nil {
		return "", "", err
	}
	return tok.Subject, tok.RawString, nil
}

// idToken allows users to either pass in an identity token directly
// or a path to an identity token via the --identity-token flag
func idToken(s string) (string, error) {
	// If this is a valid raw token or is empty, just return it
	if _, err := jwt.ParseSigned(s, []jose.SignatureAlgorithm{"RS256"}); err == nil || s == "" {
		return s, nil
	}

	// Otherwise, if this is a path to a token return the contents
	c, err := os.ReadFile(s)
	return string(c), err
}
