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
	_ "embed" // To enable the `go:embed` directive.
	"encoding/json"
	"fmt"
	"os"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/ctutil"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
	"github.com/pkg/errors"

	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/pkg/cosign"
	fulcioClient "github.com/sigstore/fulcio/pkg/generated/client"
)

// This is the CT log public key
//go:embed ctfe.pub
var ctPublicKey string

// verifySCT verifies the SCT against the Fulcio CT log public key
// The SCT is a `Signed Certificate Timestamp`, which promises that
// the certificate issued by Fulcio was also added to the public CT log within
// some defined time period
func verifySCT(certPEM, rawSCT []byte) error {
	pubKey, err := cosign.PemToECDSAKey([]byte(ctPublicKey))
	if err != nil {
		return err
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

func NewSigner(ctx context.Context, idToken, oidcIssuer, oidcClientID string, fClient *fulcioClient.Fulcio) (*fulcio.Signer, error) {
	fs, err := fulcio.NewSigner(ctx, idToken, oidcIssuer, oidcClientID, fClient)
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
