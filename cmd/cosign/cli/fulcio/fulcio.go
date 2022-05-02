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
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"net/url"
	"os"

	"github.com/pkg/errors"
	"golang.org/x/term"

	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio/fulcioroots"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/providers"
	"github.com/sigstore/fulcio/pkg/api"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"github.com/sigstore/sigstore/pkg/signature"
)

const (
	FlowNormal = "normal"
	FlowDevice = "device"
	FlowToken  = "token"
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

func getCertForOauthID(priv *ecdsa.PrivateKey, fc api.Client, connector oidcConnector, oidcIssuer, oidcClientID, oidcClientSecret, oidcRedirectURL string) (*api.CertificateResponse, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}

	tok, err := connector.OIDConnect(oidcIssuer, oidcClientID, oidcClientSecret, oidcRedirectURL)
	if err != nil {
		return nil, err
	}

	// Sign the email address as part of the request
	h := sha256.Sum256([]byte(tok.Subject))
	proof, err := ecdsa.SignASN1(rand.Reader, priv, h[:])
	if err != nil {
		return nil, err
	}

	cr := api.CertificateRequest{
		PublicKey: api.Key{
			Algorithm: "ecdsa",
			Content:   pubBytes,
		},
		SignedEmailAddress: proof,
	}

	return fc.SigningCert(cr, tok.RawString)
}

// GetCert returns the PEM-encoded signature of the OIDC identity returned as part of an interactive oauth2 flow plus the PEM-encoded cert chain.
func GetCert(ctx context.Context, priv *ecdsa.PrivateKey, idToken, flow, oidcIssuer, oidcClientID, oidcClientSecret, oidcRedirectURL string, fClient api.Client) (*api.CertificateResponse, error) {
	c := &realConnector{}
	switch flow {
	case FlowDevice:
		c.flow = oauthflow.NewDeviceFlowTokenGetter(
			oidcIssuer, oauthflow.SigstoreDeviceURL, oauthflow.SigstoreTokenURL)
	case FlowNormal:
		c.flow = oauthflow.DefaultIDTokenGetter
	case FlowToken:
		c.flow = &oauthflow.StaticTokenGetter{RawToken: idToken}
	default:
		return nil, fmt.Errorf("unsupported oauth flow: %s", flow)
	}

	return getCertForOauthID(priv, fClient, c, oidcIssuer, oidcClientID, oidcClientSecret, oidcRedirectURL)
}

type Signer struct {
	Cert  []byte
	Chain []byte
	SCT   []byte
	pub   *ecdsa.PublicKey
	*signature.ECDSASignerVerifier
}

func NewSigner(ctx context.Context, ko options.KeyOpts) (*Signer, error) {
	fClient, err := NewClient(ko.FulcioURL)
	if err != nil {
		return nil, errors.Wrap(err, "creating Fulcio client")
	}

	idToken := ko.IDToken
	// If token is not set in the options, get one from the provders
	if idToken == "" && providers.Enabled(ctx) {
		idToken, err = providers.Provide(ctx, "sigstore")
		if err != nil {
			return nil, errors.Wrap(err, "fetching ambient OIDC credentials")
		}
	}

	priv, err := cosign.GeneratePrivateKey()
	if err != nil {
		return nil, errors.Wrap(err, "generating cert")
	}
	signer, err := signature.LoadECDSASignerVerifier(priv, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	fmt.Fprintln(os.Stderr, "Retrieving signed certificate...")

	var flow string
	switch {
	case ko.FulcioAuthFlow != "":
		// Caller manually set flow option.
		flow = ko.FulcioAuthFlow
	case idToken != "":
		flow = FlowToken
	case !term.IsTerminal(0):
		fmt.Fprintln(os.Stderr, "Non-interactive mode detected, using device flow.")
		flow = FlowDevice
	default:
		flow = FlowNormal
	}
	Resp, err := GetCert(ctx, priv, idToken, flow, ko.OIDCIssuer, ko.OIDCClientID, ko.OIDCClientSecret, ko.OIDCRedirectURL, fClient) // TODO, use the chain.
	if err != nil {
		return nil, errors.Wrap(err, "retrieving cert")
	}

	f := &Signer{
		pub:                 &priv.PublicKey,
		ECDSASignerVerifier: signer,
		Cert:                Resp.CertPEM,
		Chain:               Resp.ChainPEM,
		SCT:                 Resp.SCT,
	}

	return f, nil
}

func (f *Signer) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return &f.pub, nil
}

var _ signature.Signer = &Signer{}

func GetRoots() *x509.CertPool {
	return fulcioroots.Get()
}

func GetIntermediates() *x509.CertPool {
	return fulcioroots.GetIntermediates()
}

func NewClient(fulcioURL string) (api.Client, error) {
	fulcioServer, err := url.Parse(fulcioURL)
	if err != nil {
		return nil, err
	}
	fClient := api.NewClient(fulcioServer, api.WithUserAgent(options.UserAgent()))
	return fClient, nil
}
