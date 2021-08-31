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
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	_ "embed" // To enable the `go:embed` directive.
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"sync"

	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/ctutil"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
	"github.com/pkg/errors"
	"golang.org/x/term"

	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/tuf"
	fulcioClient "github.com/sigstore/fulcio/pkg/generated/client"
	"github.com/sigstore/fulcio/pkg/generated/client/operations"
	"github.com/sigstore/fulcio/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"github.com/sigstore/sigstore/pkg/signature"
)

const (
	FlowNormal = "normal"
	FlowDevice = "device"
	FlowToken  = "token"
	altRoot    = "SIGSTORE_ROOT_FILE"
)

type Resp struct {
	CertPEM  []byte
	ChainPEM []byte
	SCT      []byte
}

// This is the root in the fulcio project.
//go:embed fulcio.pem
var rootPem string

var ctPublicKeyStr = `ctfe.pub`
var fulcioTargetStr = `fulcio.crt.pem`

var (
	// For testing
	VerifySCT = verifySCT
)

type oidcConnector interface {
	OIDConnect(string, string, string) (*oauthflow.OIDCIDToken, error)
}

type realConnector struct {
	flow oauthflow.TokenGetter
}

func (rf *realConnector) OIDConnect(url, clientID, secret string) (*oauthflow.OIDCIDToken, error) {
	return oauthflow.OIDConnect(url, clientID, secret, rf.flow)
}

type signingCertProvider interface {
	SigningCert(params *operations.SigningCertParams, authInfo runtime.ClientAuthInfoWriter, opts ...operations.ClientOption) (*operations.SigningCertCreated, error)
}

func getCertForOauthID(priv *ecdsa.PrivateKey, scp signingCertProvider, connector oidcConnector, oidcIssuer string, oidcClientID string) (Resp, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return Resp{}, err
	}

	tok, err := connector.OIDConnect(oidcIssuer, oidcClientID, "")
	if err != nil {
		return Resp{}, err
	}

	// Sign the email address as part of the request
	h := sha256.Sum256([]byte(tok.Subject))
	proof, err := ecdsa.SignASN1(rand.Reader, priv, h[:])
	if err != nil {
		return Resp{}, err
	}

	bearerAuth := httptransport.BearerToken(tok.RawString)

	content := strfmt.Base64(pubBytes)
	signedChallenge := strfmt.Base64(proof)
	params := operations.NewSigningCertParams()
	params.SetCertificateRequest(
		&models.CertificateRequest{
			PublicKey: &models.CertificateRequestPublicKey{
				Algorithm: models.CertificateRequestPublicKeyAlgorithmEcdsa,
				Content:   &content,
			},
			SignedEmailAddress: &signedChallenge,
		},
	)

	resp, err := scp.SigningCert(params, bearerAuth)
	if err != nil {
		return Resp{}, err
	}
	sct, err := base64.StdEncoding.DecodeString(resp.SCT.String())
	if err != nil {
		return Resp{}, err
	}

	// split the cert and the chain
	certBlock, chainPem := pem.Decode([]byte(resp.Payload))
	certPem := pem.EncodeToMemory(certBlock)
	fr := Resp{
		CertPEM:  certPem,
		ChainPEM: chainPem,
		SCT:      sct,
	}

	// verify the sct
	if err := VerifySCT(fr); err != nil {
		fmt.Printf("Unable to verify SCT: %v\n", err)
	} else {
		fmt.Println("Successfully verified SCT...")
	}
	return fr, nil
}

// verifySCT verifies the SCT against the Fulcio CT log public key
// The SCT is a `Signed Certificate Timestamp`, which promises that
// the certificate issued by Fulcio was also added to the public CT log within
// some defined time period
func verifySCT(fr Resp) error {
	buf := tuf.ByteDestination{Buffer: &bytes.Buffer{}}
	if err := tuf.GetTarget(context.TODO(), ctPublicKeyStr, &buf); err != nil {
		fmt.Println("Unable to verify SCT, try running `cosign init`...")
		return err
	}
	pubKey, err := cosign.PemToECDSAKey(buf.Bytes())
	if err != nil {
		return err
	}
	cert, err := x509util.CertificateFromPEM(fr.CertPEM)
	if err != nil {
		return err
	}
	var sct ct.SignedCertificateTimestamp
	if err := json.Unmarshal(fr.SCT, &sct); err != nil {
		return errors.Wrap(err, "unmarshal")
	}
	return ctutil.VerifySCT(pubKey, []*ctx509.Certificate{cert}, &sct, false)
}

// GetCert returns the PEM-encoded signature of the OIDC identity returned as part of an interactive oauth2 flow plus the PEM-encoded cert chain.
func GetCert(ctx context.Context, priv *ecdsa.PrivateKey, idToken, flow, oidcIssuer, oidcClientID string, fClient *fulcioClient.Fulcio) (Resp, error) {
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
		return Resp{}, fmt.Errorf("unsupported oauth flow: %s", flow)
	}

	return getCertForOauthID(priv, fClient.Operations, c, oidcIssuer, oidcClientID)
}

type Signer struct {
	Cert  []byte
	Chain []byte
	SCT   []byte
	pub   *ecdsa.PublicKey
	*signature.ECDSASignerVerifier
}

func NewSigner(ctx context.Context, idToken, oidcIssuer, oidcClientID string, fClient *fulcioClient.Fulcio) (*Signer, error) {
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
	case idToken != "":
		flow = FlowToken
	case !term.IsTerminal(0):
		fmt.Fprintln(os.Stderr, "Non-interactive mode detected, using device flow.")
		flow = FlowDevice
	default:
		flow = FlowNormal
	}
	Resp, err := GetCert(ctx, priv, idToken, flow, oidcIssuer, oidcClientID, fClient) // TODO, use the chain.
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

var (
	rootsOnce sync.Once
	roots     *x509.CertPool
)

func GetRoots() *x509.CertPool {
	rootsOnce.Do(func() {
		roots = initRoots()
	})
	return roots
}

func initRoots() *x509.CertPool {
	cp := x509.NewCertPool()
	rootEnv := os.Getenv(altRoot)
	if rootEnv != "" {
		raw, err := ioutil.ReadFile(rootEnv)
		if err != nil {
			panic(fmt.Sprintf("error reading root PEM file: %s", err))
		}
		if !cp.AppendCertsFromPEM(raw) {
			panic("error creating root cert pool")
		}
	} else {
		// First try retrieving from TUF root. Otherwise use rootPem.
		ctx := context.Background() // TODO: pass in context?
		buf := tuf.ByteDestination{Buffer: &bytes.Buffer{}}
		err := tuf.GetTarget(ctx, fulcioTargetStr, &buf)
		if err != nil {
			// The user may not have initialized the local root metadata. Log the error and use the embedded root.
			fmt.Fprintln(os.Stderr, "No TUF root installed, using embedded CA certificate.")
			if !cp.AppendCertsFromPEM([]byte(rootPem)) {
				panic("error creating root cert pool")
			}
		} else {
			// TODO: Remove the string replace when SigStore root is updated.
			replaced := strings.ReplaceAll(buf.String(), "\n  ", "\n")
			if !cp.AppendCertsFromPEM([]byte(replaced)) {
				panic("error creating root cert pool")
			}
		}
	}
	return cp
}
