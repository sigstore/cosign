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
	"crypto/x509"
	"fmt"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/internal/ui"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

func NewSigner(ctx context.Context, ko options.KeyOpts, signer signature.SignerVerifier) (*fulcio.Signer, error) {
	fs, err := fulcio.NewSigner(ctx, ko, signer)
	if err != nil {
		return nil, err
	}

	if ko.TrustedMaterial != nil && len(fs.SCT) == 0 {
		// Detached SCTs cannot be verified with this function.
		chain, err := cryptoutils.UnmarshalCertificatesFromPEM(fs.Chain)
		if err != nil {
			return nil, fmt.Errorf("unmarshalling cert chain from PEM for SCT verification: %w", err)
		}
		certs, err := cryptoutils.UnmarshalCertificatesFromPEM(fs.Cert)
		if err != nil || len(certs) < 1 {
			return nil, fmt.Errorf("unmarshalling cert from PEM for SCT verification: %w", err)
		}
		chain = append(certs, chain...)
		chains := make([][]*x509.Certificate, 1)
		chains[0] = chain
		if err := verify.VerifySignedCertificateTimestamp(chains, 1, ko.TrustedMaterial); err != nil {
			return nil, fmt.Errorf("verifying SCT using trusted root: %w", err)
		}
		ui.Infof(ctx, "Successfully verified SCT...")
		return fs, nil
	}

	// There was no trusted_root.json or we need to verify a detached SCT, so grab the PublicKeys for the CTFE, either from tuf or env.
	pubKeys, err := cosign.GetCTLogPubs(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting CTFE public keys: %w", err)
	}
	// verify the sct
	if err := cosign.VerifySCT(ctx, fs.Cert, fs.Chain, fs.SCT, pubKeys); err != nil {
		return nil, fmt.Errorf("verifying SCT: %w", err)
	}
	ui.Infof(ctx, "Successfully verified SCT...")

	return fs, nil
}
