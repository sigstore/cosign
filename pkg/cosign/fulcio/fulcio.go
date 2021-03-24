/*
Copyright The Sigstore Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
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

func GetCert(ctx context.Context, priv *ecdsa.PrivateKey) (string, string, error) {
	fcli, err := app.GetFulcioClient(fulcioServer())
	if err != nil {
		return "", "", err
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return "", "", err
	}
	provider, err := oidc.NewProvider(ctx, "https://accounts.google.com")
	if err != nil {
		return "", "", err
	}

	// TODO: Switch these to be creds from the sigstore project.
	config := oauth2.Config{
		ClientID: "237800849078-rmntmr1b2tcu20kpid66q5dbh1vdt7aj.apps.googleusercontent.com",
		// THIS IS NOT A SECRET - IT IS USED IN THE NATIVE/DESKTOP FLOW.
		ClientSecret: "CkkuDoCgE2D_CCRRMyF_UIhS",
		Endpoint:     provider.Endpoint(),
		RedirectURL:  "http://127.0.0.1:5556/auth/google/callback",
		Scopes:       []string{oidc.ScopeOpenID, "email"},
	}

	idToken, err := oauthflow.GetIDToken(provider, config)
	if err != nil {
		return "", "", err
	}

	var claims struct {
		Email    string `json:"email"`
		Verified bool   `json:"email_verified"`
	}
	if err := idToken.ParsedToken.Claims(&claims); err != nil {
		return "", "", err
	}
	if !claims.Verified {
		return "", "", errors.New("email not verified by identity provider")
	}

	// Sign the email address as part of the request
	h := sha256.Sum256([]byte(claims.Email))
	proof, err := ecdsa.SignASN1(rand.Reader, priv, h[:])
	if err != nil {
		return "", "", err
	}

	bearerAuth := httptransport.BearerToken(idToken.RawString)

	content := strfmt.Base64(pubBytes)
	email := strfmt.Base64(proof)
	params := operations.NewSigningCertParams()
	params.SetCertificateRequest(
		&models.CertificateRequest{
			PublicKey: &models.CertificateRequestPublicKey{
				Algorithm: swag.String(models.CertificateRequestPublicKeyAlgorithmEcdsa),
				Content:   &content,
			},
			SignedEmailAddress: &email,
		},
	)

	resp, err := fcli.Operations.SigningCert(params, bearerAuth)
	if err != nil {
		return "", "", err
	}

	// split the cert and the chain
	certBlock, chainPem := pem.Decode([]byte(resp.Payload))
	certPem := pem.EncodeToMemory(certBlock)
	return string(certPem), string(chainPem), nil
}

var Roots *x509.CertPool

func init() {
	cp := x509.NewCertPool()
	if !cp.AppendCertsFromPEM([]byte(rootPem)) {
		panic("error creating root cert pool")
	}
	Roots = cp
}
