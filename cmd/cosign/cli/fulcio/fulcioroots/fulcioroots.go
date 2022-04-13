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

package fulcioroots

import (
	"bytes"
	"context"
	"crypto/x509"
	"os"
	"sync"

	"github.com/pkg/errors"
	"github.com/sigstore/cosign/pkg/cosign/tuf"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

var (
	rootsOnce     sync.Once
	roots         *x509.CertPool
	intermediates *x509.CertPool
)

// This is the root in the fulcio project.
var fulcioTargetStr = `fulcio.crt.pem`

// This is the v1 migrated root.
var fulcioV1TargetStr = `fulcio_v1.crt.pem`

const (
	altRoot = "SIGSTORE_ROOT_FILE"
)

func Get() *x509.CertPool {
	rootsOnce.Do(func() {
		var err error
		roots, intermediates, err = initRoots()
		if err != nil {
			panic(err)
		}
	})
	return roots
}

func GetIntermediates() *x509.CertPool {
	rootsOnce.Do(func() {
		var err error
		roots, intermediates, err = initRoots()
		if err != nil {
			panic(err)
		}
	})
	return intermediates
}

func initRoots() (*x509.CertPool, *x509.CertPool, error) {
	rootPool := x509.NewCertPool()
	intermediatePool := x509.NewCertPool()

	rootEnv := os.Getenv(altRoot)
	if rootEnv != "" {
		raw, err := os.ReadFile(rootEnv)
		if err != nil {
			return nil, nil, errors.Wrap(err, "error reading root PEM file")
		}
		certs, err := cryptoutils.UnmarshalCertificatesFromPEM(raw)
		if err != nil {
			return nil, nil, errors.Wrap(err, "error unmarshalling certificates")
		}
		for _, cert := range certs {
			// root certificates are self-signed
			if bytes.Equal(cert.RawSubject, cert.RawIssuer) {
				rootPool.AddCert(cert)
			} else {
				intermediatePool.AddCert(cert)
			}
		}
	} else {
		tufClient, err := tuf.NewFromEnv(context.Background())
		if err != nil {
			return nil, nil, errors.Wrap(err, "initializing tuf")
		}
		defer tufClient.Close()
		// Retrieve from the embedded or cached TUF root. If expired, a network
		// call is made to update the root.
		targets, err := tufClient.GetTargetsByMeta(tuf.Fulcio, []string{fulcioTargetStr, fulcioV1TargetStr})
		if err != nil {
			return nil, nil, errors.New("error getting targets")
		}
		if len(targets) == 0 {
			return nil, nil, errors.New("none of the Fulcio roots have been found")
		}
		for _, t := range targets {
			certs, err := cryptoutils.UnmarshalCertificatesFromPEM(t.Target)
			if err != nil {
				return nil, nil, errors.Wrap(err, "error unmarshalling certificates")
			}
			for _, cert := range certs {
				// root certificates are self-signed
				if bytes.Equal(cert.RawSubject, cert.RawIssuer) {
					rootPool.AddCert(cert)
				} else {
					intermediatePool.AddCert(cert)
				}
			}
		}
	}
	return rootPool, intermediatePool, nil
}
