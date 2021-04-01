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
	"os"

	"github.com/sigstore/sigstore/pkg/oauthflow"

	"github.com/sigstore/fulcio/cmd/client/app"

	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/sigstore/fulcio/pkg/generated/client/operations"
	"github.com/sigstore/fulcio/pkg/generated/models"
)

const defaultFulcioAddress = "https://fulcio-dev.sigstore.dev"

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

type oidcFlow interface {
	OIDConnect(string, string, string) (*oauthflow.OIDCIDToken, string, error)
}

type defaultFlow struct{}

func (df *defaultFlow) OIDConnect(url, clientID, secret string) (*oauthflow.OIDCIDToken, string, error) {
	return oauthflow.OIDConnect(url, clientID, secret)
}

type signingCertProvider interface {
	SigningCert(params *operations.SigningCertParams, authInfo runtime.ClientAuthInfoWriter) (*operations.SigningCertCreated, error)
}

func getCertForOauthID(priv *ecdsa.PrivateKey, scp signingCertProvider, flow oidcFlow) (string, string, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return "", "", err
	}

	tok, email, err := flow.OIDConnect("https://oauth2.sigstore.dev/auth", "sigstore", "")
	if err != nil {
		return "", "", err
	}

	// Sign the email address as part of the request
	h := sha256.Sum256([]byte(email))
	proof, err := ecdsa.SignASN1(rand.Reader, priv, h[:])
	if err != nil {
		return "", "", err
	}

	bearerAuth := httptransport.BearerToken(tok.RawString)

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

	flow := &defaultFlow{}

	return getCertForOauthID(priv, fcli.Operations, flow)
}

var Roots *x509.CertPool

func init() {
	cp := x509.NewCertPool()
	if !cp.AppendCertsFromPEM([]byte(rootPem)) {
		panic("error creating root cert pool")
	}
	Roots = cp
}
