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
	"context"
	"crypto/x509"
	"os"
	"sync"

	"github.com/pkg/errors"
	"github.com/sigstore/cosign/pkg/cosign/tuf"
)

var (
	rootsOnce sync.Once
	roots     *x509.CertPool
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
		roots, err = initRoots()
		if err != nil {
			panic(err)
		}
	})
	return roots
}

func initRoots() (*x509.CertPool, error) {
	cp := x509.NewCertPool()
	rootEnv := os.Getenv(altRoot)
	if rootEnv != "" {
		raw, err := os.ReadFile(rootEnv)
		if err != nil {
			return nil, errors.Wrap(err, "error reading root PEM file")
		}
		if !cp.AppendCertsFromPEM(raw) {
			return nil, errors.New("error creating root cert pool")
		}
	} else {
		tuf, err := tuf.NewFromEnv(context.Background())
		if err != nil {
			return nil, errors.Wrap(err, "initializing tuf")
		}
		defer tuf.Close()
		// Retrieve from the embedded or cached TUF root. If expired, a network
		// call is made to update the root.
		rootFound := false
		for _, fulcioTarget := range []string{fulcioTargetStr, fulcioV1TargetStr} {
			b, err := tuf.GetTarget(fulcioTarget)
			if err == nil {
				rootFound = true
				if !cp.AppendCertsFromPEM(b) {
					return nil, errors.New("error creating root cert pool")
				}
			}
		}
		if !rootFound {
			return nil, errors.New("none of the Fulcio roots have been found")
		}
	}
	return cp, nil
}
