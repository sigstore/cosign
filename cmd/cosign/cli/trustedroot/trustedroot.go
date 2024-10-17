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
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/cryptoutils"

	"github.com/sigstore/cosign/v2/pkg/cosign"
)

type CreateCmd struct {
	CertChain        []string
	CtfeKeyPath      []string
	CtfeStartTime    []string
	Out              string
	RekorKeyPath     []string
	RekorStartTime   []string
	TSACertChainPath []string
}

func (c *CreateCmd) Exec(_ context.Context) error {
	var fulcioCertAuthorities []root.CertificateAuthority
	ctLogs := make(map[string]*root.TransparencyLog)
	var timestampAuthorities []root.CertificateAuthority
	rekorTransparencyLogs := make(map[string]*root.TransparencyLog)

	for i := 0; i < len(c.CertChain); i++ {
		fulcioAuthority, err := parsePEMFile(c.CertChain[i])
		if err != nil {
			return err
		}
		fulcioCertAuthorities = append(fulcioCertAuthorities, *fulcioAuthority)
	}

	for i := 0; i < len(c.CtfeKeyPath); i++ {
		ctLogPubKey, id, idBytes, err := getPubKey(c.CtfeKeyPath[i])
		if err != nil {
			return err
		}

		startTime := time.Unix(0, 0)

		if i < len(c.CtfeStartTime) {
			startTime, err = time.Parse(time.RFC3339, c.CtfeStartTime[i])
			if err != nil {
				return err
			}
		}

		ctLogs[id] = &root.TransparencyLog{
			HashFunc:            crypto.SHA256,
			ID:                  idBytes,
			ValidityPeriodStart: startTime,
			PublicKey:           *ctLogPubKey,
			SignatureHashFunc:   crypto.SHA256,
		}
	}

	for i := 0; i < len(c.RekorKeyPath); i++ {
		tlogPubKey, id, idBytes, err := getPubKey(c.RekorKeyPath[i])
		if err != nil {
			return err
		}

		startTime := time.Unix(0, 0)

		if i < len(c.RekorStartTime) {
			startTime, err = time.Parse(time.RFC3339, c.RekorStartTime[i])
			if err != nil {
				return err
			}
		}

		rekorTransparencyLogs[id] = &root.TransparencyLog{
			HashFunc:            crypto.SHA256,
			ID:                  idBytes,
			ValidityPeriodStart: startTime,
			PublicKey:           *tlogPubKey,
			SignatureHashFunc:   crypto.SHA256,
		}
	}

	for i := 0; i < len(c.TSACertChainPath); i++ {
		timestampAuthority, err := parsePEMFile(c.TSACertChainPath[i])
		if err != nil {
			return err
		}
		timestampAuthorities = append(timestampAuthorities, *timestampAuthority)
	}

	newTrustedRoot, err := root.NewTrustedRoot(root.TrustedRootMediaType01,
		fulcioCertAuthorities, ctLogs, timestampAuthorities,
		rekorTransparencyLogs,
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
		fmt.Println(string(trBytes))
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
	ca.ValidityPeriodStart = certs[len(certs)-1].NotBefore
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

	for block, contents := pem.Decode(contents); block != nil; block, contents = pem.Decode(contents) {
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

func getPubKey(path string) (*crypto.PublicKey, string, []byte, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, "", []byte{}, err
	}

	pubKey, err := cryptoutils.UnmarshalPEMToPublicKey(pemBytes)
	if err != nil {
		return nil, "", []byte{}, err
	}

	keyID, err := cosign.GetTransparencyLogID(pubKey)
	if err != nil {
		return nil, "", []byte{}, err
	}

	idBytes, err := hex.DecodeString(keyID)
	if err != nil {
		return nil, "", []byte{}, err
	}

	return &pubKey, keyID, idBytes, nil
}
