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

package cosign

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/sigstore/cosign/v2/pkg/cosign/env"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	tufv1 "github.com/sigstore/sigstore/pkg/tuf"
)

const (
	tsaLeafCertStr                = `tsa_leaf.crt.pem`
	tsaRootCertStr                = `tsa_root.crt.pem`
	tsaIntermediateCertStrPattern = `tsa_intermediate_%d.crt.pem`
)

type TSACertificates struct {
	LeafCert          *x509.Certificate
	IntermediateCerts []*x509.Certificate
	RootCert          []*x509.Certificate
}

// GetTSACerts retrieves trusted TSA certificates from the embedded or cached
// TUF root. If expired, makes a network call to retrieve the updated targets.
// By default, the certificates come from TUF, but you can override this for test
// purposes by using an env variable `SIGSTORE_TSA_CERTIFICATE_FILE` or a file path
// specified in `TSACertChainPath`. If using an alternate, the file should be in PEM format.
func GetTSACerts(ctx context.Context, certChainPath string) (*TSACertificates, error) {
	altTSACert := env.Getenv(env.VariableSigstoreTSACertificateFile)

	var raw []byte
	var err error
	switch {
	case altTSACert != "":
		raw, err = os.ReadFile(altTSACert)
	case certChainPath != "":
		raw, err = os.ReadFile(certChainPath)
	}
	if err != nil {
		return nil, fmt.Errorf("error reading TSA certificate file: %w", err)
	}
	if len(raw) > 0 {
		leaves, intermediates, roots, err := splitPEMCertificateChain(raw)
		if err != nil {
			return nil, fmt.Errorf("error splitting TSA certificates: %w", err)
		}
		if len(leaves) != 1 {
			return nil, fmt.Errorf("TSA certificate chain must contain exactly one leaf certificate")
		}

		if len(roots) == 0 {
			return nil, fmt.Errorf("TSA certificate chain must contain at least one root certificate")
		}
		return &TSACertificates{
			LeafCert:          leaves[0],
			IntermediateCerts: intermediates,
			RootCert:          roots,
		}, nil
	}

	if useNewTUFClient() {
		opts, err := setTUFOpts()
		if err != nil {
			return nil, fmt.Errorf("error setting TUF options: %w", err)
		}
		trustedRoot, _ := root.NewLiveTrustedRoot(opts)
		if trustedRoot == nil {
			certs, err := getTSAKeysFromTUF(opts)
			if err != nil {
				return nil, fmt.Errorf("error adding TSA certs from TUF targets: %w", err)
			}
			return certs, nil
		}
		tsas := trustedRoot.TimestampingAuthorities()
		if len(tsas) < 1 {
			return nil, fmt.Errorf("could not find timestamp authorities in trusted root")
		}
		return &TSACertificates{
			LeafCert:          tsas[0].Leaf,
			IntermediateCerts: tsas[0].Intermediates,
			RootCert:          []*x509.Certificate{tsas[0].Root},
		}, nil
	}

	certs, err := legacyGetTSAKeysFromTUF(ctx)
	if err != nil {
		return nil, fmt.Errorf("error adding TSA certs from TUF (v1) targets: %w", err)
	}
	return certs, nil
}

// splitPEMCertificateChain returns a list of leaf (non-CA) certificates, a certificate pool for
// intermediate CA certificates, and a certificate pool for root CA certificates
func splitPEMCertificateChain(pem []byte) (leaves, intermediates, roots []*x509.Certificate, err error) {
	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(pem)
	if err != nil {
		return nil, nil, nil, err
	}

	for _, cert := range certs {
		if !cert.IsCA {
			leaves = append(leaves, cert)
		} else {
			// root certificates are self-signed
			if bytes.Equal(cert.RawSubject, cert.RawIssuer) {
				roots = append(roots, cert)
			} else {
				intermediates = append(intermediates, cert)
			}
		}
	}

	return leaves, intermediates, roots, nil
}

func getTSAKeysFromTUF(opts *tuf.Options) (*TSACertificates, error) {
	tufClient, err := tuf.New(opts)
	if err != nil {
		return nil, fmt.Errorf("error creating TUF client: %w", err)
	}
	leafCertBytes, err := tufClient.GetTarget(tsaLeafCertStr)
	if err != nil {
		return nil, fmt.Errorf("error fetching TSA leaf cert: %w", err)
	}
	rootCertBytes, err := tufClient.GetTarget(tsaRootCertStr)
	if err != nil {
		return nil, fmt.Errorf("error fetching TSA root CA cert: %w", err)
	}
	var intermediateChainBytes []byte
	for i := 0; ; i++ {
		intermediateCertStr := fmt.Sprintf(tsaIntermediateCertStrPattern, i)
		intermediateCertBytes, _ := tufClient.GetTarget(intermediateCertStr)
		if len(intermediateCertBytes) == 0 {
			break
		}
		intermediateChainBytes = append(intermediateChainBytes, intermediateCertBytes...)
	}
	leafCert, err := cryptoutils.UnmarshalCertificatesFromPEM(leafCertBytes)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling TSA leaf cert: %w", err)
	}
	rootCert, err := cryptoutils.UnmarshalCertificatesFromPEM(rootCertBytes)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling TSA root CA cert: %w", err)
	}
	var intermediates []*x509.Certificate
	if len(intermediateChainBytes) > 0 {
		intermediates, err = cryptoutils.UnmarshalCertificatesFromPEM(intermediateChainBytes)
		if err != nil {
			return nil, fmt.Errorf("error unmarshalling intermediate certs: %w", err)
		}
	}
	return &TSACertificates{
		LeafCert:          leafCert[0],
		IntermediateCerts: intermediates,
		RootCert:          rootCert,
	}, nil
}

func legacyGetTSAKeysFromTUF(ctx context.Context) (*TSACertificates, error) {
	tufClient, err := tufv1.NewFromEnv(ctx)
	if err != nil {
		return nil, fmt.Errorf("error creating legacy TUF client: %w", err)
	}
	targets, err := tufClient.GetTargetsByMeta(tufv1.TSA, []string{tsaLeafCertStr, tsaRootCertStr})
	if err != nil {
		return nil, fmt.Errorf("error fetching TSA certs: %w", err)
	}
	var buffer bytes.Buffer
	for _, t := range targets {
		buffer.Write(t.Target)
		buffer.WriteByte('\n')
	}
	for i := 0; ; i++ {
		target, err := tufClient.GetTarget(fmt.Sprintf(tsaIntermediateCertStrPattern, i))
		if err != nil {
			break
		}
		buffer.Write(target)
		buffer.WriteByte('\n')
	}
	if buffer.Len() == 0 {
		return nil, fmt.Errorf("could not find TSA keys")
	}
	leaves, intermediates, roots, err := splitPEMCertificateChain(buffer.Bytes())
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling TSA certs: %w", err)
	}
	return &TSACertificates{
		LeafCert:          leaves[0],
		IntermediateCerts: intermediates,
		RootCert:          roots,
	}, nil
}
