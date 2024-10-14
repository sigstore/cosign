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
	"crypto/x509"
	"fmt"
	"os"

	"github.com/sigstore/cosign/v2/pkg/cosign/env"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/fulcioroots"
)

const (
	// This is the root in the fulcio project.
	fulcioTargetStr = `fulcio.crt.pem`
	// This is the v1 migrated root.
	fulcioV1TargetStr = `fulcio_v1.crt.pem`
	// This is the untrusted v1 intermediate CA certificate, used or chain building.
	fulcioV1IntermediateTargetStr = `fulcio_intermediate_v1.crt.pem`
)

func GetFulcioCerts() (*x509.CertPool, *x509.CertPool, error) {
	rootEnv := env.Getenv(env.VariableSigstoreRootFile)
	if rootEnv != "" {
		return getFulcioCertsFromFile(rootEnv)
	}

	if useNewTUFClient() {
		opts, err := setTUFOpts()
		if err != nil {
			return nil, nil, fmt.Errorf("error setting TUF options: %w", err)
		}
		trustedRoot, _ := root.NewLiveTrustedRoot(opts)
		if trustedRoot == nil {
			rootPool, intermediates, err := getFulcioCertsFromTUF(opts)
			if err != nil {
				return nil, nil, fmt.Errorf("error getting Fulcio certs from TUF targets: %w", err)
			}
			return rootPool, intermediates, nil
		}
		rootPool := x509.NewCertPool()
		var intermediatePool *x509.CertPool
		cas := trustedRoot.FulcioCertificateAuthorities()
		if len(cas) < 1 {
			return nil, nil, fmt.Errorf("could not find Fulcio certificate authorities in trusted root")
		}
		for _, ca := range cas {
			rootPool.AddCert(ca.Root)
			for _, i := range ca.Intermediates {
				if intermediatePool == nil {
					intermediatePool = x509.NewCertPool()
				}
				intermediatePool.AddCert(i)
			}
		}
		return rootPool, intermediatePool, nil
	}

	roots, intermediates, err := legacyGetFulcioCertsFromTUF()
	if err != nil {
		return nil, nil, fmt.Errorf("error getting Fulcio certs from TUF (v1) targets: %w", err)
	}
	return roots, intermediates, nil
}

func getFulcioCertsFromFile(path string) (*x509.CertPool, *x509.CertPool, error) {
	rootPool := x509.NewCertPool()
	// intermediatePool should be nil if no intermediates are found
	var intermediatePool *x509.CertPool
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading root PEM file: %w", err)
	}
	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("error unmarshalling certificates: %w", err)
	}
	for _, cert := range certs {
		// root certificates are self-signed
		if bytes.Equal(cert.RawSubject, cert.RawIssuer) {
			rootPool.AddCert(cert)
		} else {
			if intermediatePool == nil {
				intermediatePool = x509.NewCertPool()
			}
			intermediatePool.AddCert(cert)
		}
	}
	return rootPool, intermediatePool, nil
}

func getFulcioCertsFromTUF(opts *tuf.Options) (*x509.CertPool, *x509.CertPool, error) {
	tufClient, err := tuf.New(opts)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating TUF client: %w", err)
	}
	rootPool := x509.NewCertPool()
	fulcioCertBytes, _ := tufClient.GetTarget(fulcioTargetStr)
	fulcioV1CertBytes, _ := tufClient.GetTarget(fulcioV1TargetStr)
	if len(fulcioCertBytes) > 0 {
		fulcioCert, err := cryptoutils.UnmarshalCertificatesFromPEM(fulcioCertBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("error unmarshalling Fulcio cert: %w", err)
		}
		for _, c := range fulcioCert {
			rootPool.AddCert(c)
		}
	}
	if len(fulcioV1CertBytes) > 0 {
		fulcioV1Cert, err := cryptoutils.UnmarshalCertificatesFromPEM(fulcioV1CertBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("error unmarshalling Fulcio v1 cert: %w", err)
		}
		for _, c := range fulcioV1Cert {
			rootPool.AddCert(c)
		}
	}

	var intermediatePool *x509.CertPool
	fulcioIntermediateBytes, _ := tufClient.GetTarget(fulcioV1IntermediateTargetStr)
	if len(fulcioIntermediateBytes) == 0 {
		fulcioIntermediate, err := cryptoutils.UnmarshalCertificatesFromPEM(fulcioIntermediateBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("error unmarshalling Fulcio intermediate cert: %w", err)
		}
		intermediatePool = x509.NewCertPool()
		for _, c := range fulcioIntermediate {
			intermediatePool.AddCert(c)
		}
	}
	return rootPool, intermediatePool, nil
}

func legacyGetFulcioCertsFromTUF() (*x509.CertPool, *x509.CertPool, error) {
	roots, err := fulcioroots.Get()
	if err != nil {
		return nil, nil, fmt.Errorf("error getting Fulcio roots: %w", err)
	}
	intermediates, err := fulcioroots.GetIntermediates()
	if err != nil {
		return nil, nil, fmt.Errorf("error getting Fulcio intermediates: %w", err)
	}
	return roots, intermediates, err
}
