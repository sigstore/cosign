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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"golang.org/x/term"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/internal/pkg/cosign/fulcio/fulcioroots"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/providers"
	fulciopb "github.com/sigstore/fulcio/pkg/generated/protobuf"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"github.com/sigstore/sigstore/pkg/signature"
)

const (
	flowNormal = "normal"
	flowDevice = "device"
	flowToken  = "token"
	// spacing is intentional to have this indented
	privacyStatement = `
        Note that there may be personally identifiable information associated with this signed artifact.
        This may include the email address associated with the account with which you authenticate.
        This information will be used for signing this artifact and will be stored in public transparency logs and cannot be removed later.`
	privacyStatementConfirmation = "        By typing 'y', you attest that you grant (or have permission to grant) and agree to have this information stored permanently in transparency logs."
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

func getCertForOauthID(ctx context.Context, priv *ecdsa.PrivateKey, fc fulciopb.CAClient, connector oidcConnector, oidcIssuer, oidcClientID, oidcClientSecret, oidcRedirectURL string) (*fulciopb.SigningCertificate, error) {
	pubPEM, err := cryptoutils.MarshalPublicKeyToPEM(priv.Public())
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

	cscr := &fulciopb.CreateSigningCertificateRequest{
		Key: &fulciopb.CreateSigningCertificateRequest_PublicKeyRequest{
			PublicKeyRequest: &fulciopb.PublicKeyRequest{
				PublicKey: &fulciopb.PublicKey{
					Algorithm: fulciopb.PublicKeyAlgorithm_ECDSA,
					Content:   string(pubPEM),
				},
				ProofOfPossession: proof,
			},
		},
		Credentials: &fulciopb.Credentials{
			Credentials: &fulciopb.Credentials_OidcIdentityToken{
				OidcIdentityToken: tok.RawString,
			},
		},
	}

	return fc.CreateSigningCertificate(ctx, cscr)
}

// GetCert returns the PEM-encoded signature of the OIDC identity returned as part of an interactive oauth2 flow plus the PEM-encoded cert chain.
func GetCert(ctx context.Context, priv *ecdsa.PrivateKey, idToken, flow, oidcIssuer, oidcClientID, oidcClientSecret, oidcRedirectURL string, fClient fulciopb.CAClient) (*fulciopb.SigningCertificate, error) {
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

	return getCertForOauthID(ctx, priv, fClient, c, oidcIssuer, oidcClientID, oidcClientSecret, oidcRedirectURL)
}

type Signer struct {
	Cert  string
	Chain []string
	SCT   []byte
	pub   *ecdsa.PublicKey
	*signature.ECDSASignerVerifier
}

func NewSigner(ctx context.Context, ko options.KeyOpts) (*Signer, error) {
	fClient, err := NewClient(ko)
	if err != nil {
		return nil, fmt.Errorf("creating Fulcio client: %w", err)
	}

	idToken := ko.IDToken
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

	priv, err := cosign.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("generating cert: %w", err)
	}
	signer, err := signature.LoadECDSASignerVerifier(priv, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	fmt.Fprintln(os.Stderr, "Retrieving signed certificate...")

	fmt.Fprintln(os.Stderr, privacyStatement)

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
		ok, err := cosign.ConfirmPrompt(privacyStatementConfirmation, ko.SkipConfirmation)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errors.New("no confirmation")
		}
		flow = flowNormal
	}
	resp, err := GetCert(ctx, priv, idToken, flow, ko.OIDCIssuer, ko.OIDCClientID, ko.OIDCClientSecret, ko.OIDCRedirectURL, fClient)
	if err != nil {
		return nil, fmt.Errorf("retrieving cert: %w", err)
	}

	f := &Signer{
		pub:                 &priv.PublicKey,
		ECDSASignerVerifier: signer,
	}
	switch csc := resp.Certificate.(type) {
	case *fulciopb.SigningCertificate_SignedCertificateDetachedSct:
		f.SCT = csc.SignedCertificateDetachedSct.SignedCertificateTimestamp
		f.Cert = csc.SignedCertificateDetachedSct.Chain.Certificates[0]
		f.Chain = csc.SignedCertificateDetachedSct.Chain.Certificates[1:]
	case *fulciopb.SigningCertificate_SignedCertificateEmbeddedSct:
		f.Cert = csc.SignedCertificateEmbeddedSct.Chain.Certificates[0]
		f.Chain = csc.SignedCertificateEmbeddedSct.Chain.Certificates[1:]
	}

	return f, nil
}

func (f *Signer) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return &f.pub, nil
}

var _ signature.Signer = &Signer{}

func GetRoots() (*x509.CertPool, error) {
	return fulcioroots.Get()
}

func GetIntermediates() (*x509.CertPool, error) {
	return fulcioroots.GetIntermediates()
}

func NewClient(ko options.KeyOpts) (fulciopb.CAClient, error) {
	opts := []grpc.DialOption{grpc.WithUserAgent(options.UserAgent())}
	// follows https://github.com/grpc/grpc/blob/master/doc/naming.md
	// if port was not specified, use 443
	// if port is 443, presume TLS
	host := ""
	port := "443"
	// if the url has a scheme, let's parse it with url.Parse
	switch {
	case strings.Contains(ko.FulcioURL, "://"):
		fulcioServer, err := url.Parse(ko.FulcioURL)
		if err != nil {
			return nil, err
		}
		host = fulcioServer.Hostname()
		if fulcioServer.Port() != "" {
			port = fulcioServer.Port()
		} else if fulcioServer.Scheme == "http" && ko.AllowFulcioInsecure {
			port = "80"
		}
	case strings.Contains(ko.FulcioURL, ":"):
		// if the url does not have a scheme, but has a colon, let's split host and port
		parsedHost, parsedPort, err := net.SplitHostPort(ko.FulcioURL)
		if err != nil {
			return nil, err
		}
		host = parsedHost
		port = parsedPort
	default:
		// the url does not have a scheme or a colon, let's assume it's just a hostname
		host = ko.FulcioURL
	}
	target := fmt.Sprintf("%v:%v", host, port)

	// assume TLS unless flag explicitly says to use insecure
	transportCreds := credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})
	if ko.AllowFulcioInsecure {
		transportCreds = insecure.NewCredentials()
	}

	opts = append(opts, grpc.WithTransportCredentials(transportCreds))
	conn, err := grpc.Dial(target, opts...)
	if err != nil {
		return nil, err
	}
	return fulciopb.NewCAClient(conn), nil
}
