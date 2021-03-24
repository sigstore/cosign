// Copyright 2021 The Rekor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package fulcio

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	_ "embed" // To enable the `go:embed` directive.
	"encoding/pem"
	"errors"
	"os"

	"github.com/sigstore/fulcio/cmd/client/app"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/sigstore/fulcio/pkg/generated/client/operations"
	"github.com/sigstore/fulcio/pkg/generated/models"
	"github.com/sigstore/fulcio/pkg/oauthflow"
	"golang.org/x/oauth2"
)

const defaultFulcioAddress = "https://fulcio.sigstore.dev"

// This is the root in the fulcio project.
//go:embed fulcio.pem
var rootPem string

func fulcioServer() string {
	addr := os.Getenv("FULCIO_ADDRESS")
	if addr != "" {
		return addr
	}
	return defaultFulcioAddress
}

type oidcIDToken struct {
	*oauthflow.OIDCIDToken
}

func (o *oidcIDToken) email() (string, error) {
	email, verified, err := oauthflow.EmailFromIDToken(o.ParsedToken)
	if err != nil {
		return "", err
	}
	if !verified {
		return "", errors.New("email not verified by identity provider")
	}
	return email, nil
}

func (o *oidcIDToken) accessToken() string {
	return o.RawString
}

type idToken interface {
	email() (string, error)
	accessToken() string
}

type oidcTokenGetter struct {
	oidcp *oidc.Provider
}

func (tg *oidcTokenGetter) getIDToken() (idToken, error) {
	// TODO: Switch these to be creds from the sigstore project.
	config := oauth2.Config{
		ClientID: "237800849078-rmntmr1b2tcu20kpid66q5dbh1vdt7aj.apps.googleusercontent.com",
		// THIS IS NOT A SECRET - IT IS USED IN THE NATIVE/DESKTOP FLOW.
		ClientSecret: "CkkuDoCgE2D_CCRRMyF_UIhS",
		Endpoint:     tg.oidcp.Endpoint(),
		RedirectURL:  "http://127.0.0.1:5556/auth/google/callback",
		Scopes:       []string{oidc.ScopeOpenID, "email"},
	}
	token, err := oauthflow.GetIDToken(tg.oidcp, config)
	if err != nil {
		return nil, err
	}

	return &oidcIDToken{token}, nil
}

type idTokenGetter interface {
	getIDToken() (idToken, error)
}

type signingCertProvider interface {
	SigningCert(params *operations.SigningCertParams, authInfo runtime.ClientAuthInfoWriter) (*operations.SigningCertCreated, error)
}

func getCertForOauthID(priv *ecdsa.PrivateKey, idtg idTokenGetter, scp signingCertProvider) (string, string, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return "", "", err
	}

	idToken, err := idtg.getIDToken()
	if err != nil {
		return "", "", err
	}

	email, err := idToken.email()
	if err != nil {
		return "", "", err
	}

	// Sign the email address as part of the request
	h := sha256.Sum256([]byte(email))
	proof, err := ecdsa.SignASN1(rand.Reader, priv, h[:])
	if err != nil {
		return "", "", err
	}

	bearerAuth := httptransport.BearerToken(idToken.accessToken())

	content := strfmt.Base64(pubBytes)
	signedEmail := strfmt.Base64(proof)
	params := operations.NewSigningCertParams()
	params.SetCertificateRequest(
		&models.CertificateRequest{
			PublicKey: &models.CertificateRequestPublicKey{
				Algorithm: swag.String(models.CertificateRequestPublicKeyAlgorithmEcdsa),
				Content:   &content,
			},
			SignedEmailAddress: &signedEmail,
		},
	)

	resp, err := scp.SigningCert(params, bearerAuth)
	if err != nil {
		return "", "", err
	}

	// split the cert and the chain
	certBlock, chainPem := pem.Decode([]byte(resp.Payload))
	certPem := pem.EncodeToMemory(certBlock)
	return string(certPem), string(chainPem), nil
}

// GetCert returns the PEM-encoded signature of the OIDC identity returned as part of an interactive oauth2 flow plus the PEM-encoded cert chain.
func GetCert(ctx context.Context, priv *ecdsa.PrivateKey) (string, string, error) {
	fcli, err := app.GetFulcioClient(fulcioServer())
	if err != nil {
		return "", "", err
	}

	provider, err := oidc.NewProvider(ctx, "https://accounts.google.com")
	if err != nil {
		return "", "", err
	}

	return getCertForOauthID(priv, &oidcTokenGetter{provider}, fcli.Operations)
}

var Roots *x509.CertPool

func init() {
	cp := x509.NewCertPool()
	if !cp.AppendCertsFromPEM([]byte(rootPem)) {
		panic("error creating root cert pool")
	}
	Roots = cp
}
