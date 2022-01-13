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

package fulcioverifier

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/ctutil"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
	"github.com/pkg/errors"

	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/tuf"
	"github.com/sigstore/fulcio/pkg/api"
)

// This is the CT log public key target name
var ctPublicKeyStr = `ctfe.pub`

// Setting this env variable will over ride what is used to validate
// the SCT coming back from Fulcio.
const altCTLogPublicKeyLocation = "SIGSTORE_CT_LOG_PUBLIC_KEY_FILE"

// verifySCT verifies the SCT against the Fulcio CT log public key.
// By default this comes from TUF, but you can override this (for test)
// purposes by using an env variable `SIGSTORE_CT_LOG_PUBLIC_KEY_FILE`. If using
// an alternate, the file can be PEM, or DER format.
//
// The SCT is a `Signed Certificate Timestamp`, which promises that
// the certificate issued by Fulcio was also added to the public CT log within
// some defined time period
func verifySCT(certPEM, rawSCT []byte) error {
	var pubKey crypto.PublicKey
	var err error
	rootEnv := os.Getenv(altCTLogPublicKeyLocation)
	if rootEnv == "" {
		ctx := context.TODO()
		tuf, err := tuf.NewFromEnv(ctx)
		if err != nil {
			return err
		}
		defer tuf.Close()
		ctPub, err := tuf.GetTarget(ctPublicKeyStr)
		if err != nil {
			return err
		}
		// Is there a reason why this must be ECDSA key?
		pubKey, err = cosign.PemToECDSAKey(ctPub)
		if err != nil {
			return errors.Wrap(err, "converting Public CT to ECDSAKey")
		}
	} else {
		fmt.Fprintf(os.Stderr, "**Warning** Using a non-standard public key for verifying SCT: %s\n", rootEnv)
		raw, err := os.ReadFile(rootEnv)
		if err != nil {
			return errors.Wrap(err, "error reading alternate public key file")
		}
		pubKey, err = getAlternatePublicKey(raw)
		if err != nil {
			return errors.Wrap(err, "error parsing alternate public key from the file")
		}
	}
	cert, err := x509util.CertificateFromPEM(certPEM)
	if err != nil {
		return err
	}
	var sct ct.SignedCertificateTimestamp
	if err := json.Unmarshal(rawSCT, &sct); err != nil {
		return errors.Wrap(err, "unmarshal")
	}
	return ctutil.VerifySCT(pubKey, []*ctx509.Certificate{cert}, &sct, false)
}

func NewSigner(ctx context.Context, idToken, oidcIssuer, oidcClientID, oidcClientSecret string, fClient api.Client) (*fulcio.Signer, error) {
	fs, err := fulcio.NewSigner(ctx, idToken, oidcIssuer, oidcClientID, oidcClientSecret, fClient)
	if err != nil {
		return nil, err
	}

	// verify the sct
	if err := verifySCT(fs.Cert, fs.SCT); err != nil {
		return nil, errors.Wrap(err, "verifying SCT")
	}
	fmt.Fprintln(os.Stderr, "Successfully verified SCT...")

	return fs, nil
}

// Given a byte array, try to construct a public key from it.
// Will try first to see if it's PEM formatted, if not, then it will
// try to parse it as der publics, and failing that
func getAlternatePublicKey(in []byte) (crypto.PublicKey, error) {
	var pubKey crypto.PublicKey
	var err error
	var derBytes []byte
	pemBlock, _ := pem.Decode(in)
	if pemBlock == nil {
		fmt.Fprintf(os.Stderr, "Failed to decode non-standard public key for verifying SCT using PEM decode, trying as DER")
		derBytes = in
	} else {
		derBytes = pemBlock.Bytes
	}
	pubKey, err = x509.ParsePKIXPublicKey(derBytes)
	if err != nil {
		// Try using the PKCS1 before giving up.
		pubKey, err = x509.ParsePKCS1PublicKey(derBytes)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse alternate public key")
		}
	}
	return pubKey, nil
}
