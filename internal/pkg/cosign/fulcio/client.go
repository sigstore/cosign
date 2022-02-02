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

package fulcio

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"strings"

	"github.com/sigstore/cosign/internal/pkg/cosign/oidc"
	fulcioapi "github.com/sigstore/fulcio/pkg/api"
	"github.com/sigstore/sigstore/pkg/signature"
)

// *NOTE* This is a higher-level client than exists in `sigstore/fulcio`, should probably live there

// Client is a Fulcio client.
type Client struct {
	APIClient fulcioapi.Client
}

// GetCert retrieves a Fulcio certificate which associates the `Signer`'s public key with the ID provided
func (c *Client) GetCert(ctx context.Context, signer signature.Signer, oidp oidc.Provider) (cert *x509.Certificate, chain []*x509.Certificate, sct []byte, err error) {
	idToken, err := oidp.GetIDToken(ctx)
	// Sign the token's subject
	subject := ""
	// subject := idToken.Subject
	subjectSig, err := signer.SignMessage(strings.NewReader(subject))

	pub, err := signer.PublicKey()
	if _, isECDSA := pub.(*ecdsa.PublicKey); !isECDSA {
		return nil, nil, nil, errors.New("only ESCDA public keys are supported...?")
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)

	req := fulcioapi.CertificateRequest{
		PublicKey: fulcioapi.Key{
			Algorithm: "ecdsa",
			Content:   pubBytes,
		},
		SignedEmailAddress: subjectSig,
	}

	resp, err := c.APIClient.SigningCert(req, idToken.JWTEncode())
	// cert = parsex509(resp.CertPEM)
	// chain = parsex509(resp.ChainPEM)
	return cert, chain, resp.SCT, nil
}
