//
// Copyright 2024 The Sigstore Authors.
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

package trustedroot

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/v2/internal/ui"
)

type CreateCmd struct {
	CAIntermediates  string
	CARoots          string
	CertChain        string
	Out              string
	RekorURL         string
	TSACertChainPath string
}

func (c *CreateCmd) Exec(ctx context.Context) error {
	var fulcioCertAuthorities []root.CertificateAuthority
	var timestampAuthorities []root.CertificateAuthority
	rekorTransparencyLogs := make(map[string]*root.TransparencyLog)

	if c.CertChain != "" {
		fulcioAuthority, err := parsePEMFile(c.CertChain)
		if err != nil {
			return err
		}
		fulcioCertAuthorities = append(fulcioCertAuthorities, *fulcioAuthority)
	} else if c.CARoots != "" {
		roots, err := parseCerts(c.CARoots)
		if err != nil {
			return err
		}

		var intermediates []*x509.Certificate
		if c.CAIntermediates != "" {
			intermediates, err = parseCerts(c.CAIntermediates)
			if err != nil {
				return err
			}
		}

		// Here we're trying to "flatten" the x509.CertPool cosign was using
		// into a trusted root with a clear mapping between roots and
		// intermediates. Make a guess that if there are intermediates, there
		// is one per root.

		for i, rootCert := range roots {
			var fulcioAuthority root.CertificateAuthority
			fulcioAuthority.Root = rootCert
			if i < len(intermediates) {
				fulcioAuthority.Intermediates = []*x509.Certificate{intermediates[i]}
			}
			fulcioCertAuthorities = append(fulcioCertAuthorities, fulcioAuthority)
		}
	}

	if c.RekorURL != "" {
		rekorClient, err := rekor.NewClient(c.RekorURL)
		if err != nil {
			return fmt.Errorf("creating Rekor client: %w", err)
		}

		rekorPubKey, err := rekorClient.Pubkey.GetPublicKey(nil)
		if err != nil {
			return err
		}

		block, _ := pem.Decode([]byte(rekorPubKey.Payload))
		if block == nil {
			return errors.New("failed to decode public key of server")
		}

		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return err
		}

		keyHash := sha256.Sum256(block.Bytes)
		keyID := base64.StdEncoding.EncodeToString(keyHash[:])

		rekorTransparencyLog := root.TransparencyLog{
			BaseURL:           c.RekorURL,
			HashFunc:          crypto.SHA256,
			ID:                keyHash[:],
			PublicKey:         pub,
			SignatureHashFunc: crypto.SHA256,
		}

		rekorTransparencyLogs[keyID] = &rekorTransparencyLog
	}

	if c.TSACertChainPath != "" {
		timestampAuthority, err := parsePEMFile(c.TSACertChainPath)
		if err != nil {
			return err
		}
		timestampAuthorities = append(timestampAuthorities, *timestampAuthority)
	}

	newTrustedRoot, err := root.NewTrustedRoot(root.TrustedRootMediaType01,
		fulcioCertAuthorities, nil, timestampAuthorities, rekorTransparencyLogs,
	)
	if err != nil {
		return err
	}

	var trBytes []byte

	trBytes, err = newTrustedRoot.MarshalJSON()
	if err != nil {
		return err
	}

	if c.Out != "" {
		err = os.WriteFile(c.Out, trBytes, 0600)
		if err != nil {
			return err
		}
	} else {
		ui.Infof(ctx, string(trBytes))
	}

	return nil
}

func parsePEMFile(path string) (*root.CertificateAuthority, error) {
	certs, err := parseCerts(path)
	if err != nil {
		return nil, err
	}

	var ca root.CertificateAuthority
	ca.Root = certs[len(certs)-1]
	if len(certs) > 1 {
		ca.Intermediates = certs[:len(certs)-1]
	}

	return &ca, nil
}

func parseCerts(path string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	for block, contents := pem.Decode(contents); ; block, contents = pem.Decode(contents) {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)

		if len(contents) == 0 {
			break
		}
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates in file %s", path)
	}

	return certs, nil
}
