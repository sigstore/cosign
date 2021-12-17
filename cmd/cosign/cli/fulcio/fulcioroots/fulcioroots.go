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
	"fmt"
	"os"
	"sync"

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
		roots = initRoots()
	})
	return roots
}

func initRoots() *x509.CertPool {
	cp := x509.NewCertPool()
	rootEnv := os.Getenv(altRoot)
	if rootEnv != "" {
		raw, err := os.ReadFile(rootEnv)
		if err != nil {
			panic(fmt.Sprintf("error reading root PEM file: %s", err))
		}
		if !cp.AppendCertsFromPEM(raw) {
			panic("error creating root cert pool")
		}
	} else {
		// Retrieve from the embedded or cached TUF root. If expired, a network
		// call is made to update the root.
		ctx := context.Background() // TODO: pass in context?
		rootFound := false
		for _, fulcioTarget := range []string{fulcioTargetStr, fulcioV1TargetStr} {
			buf := tuf.ByteDestination{Buffer: &bytes.Buffer{}}
			if err := tuf.GetTarget(ctx, fulcioTarget, &buf); err == nil {
				rootFound = true
				if !cp.AppendCertsFromPEM(buf.Bytes()) {
					panic("error creating root cert pool")
				}
			}
		}
		if !rootFound {
			panic("none of the Fulcio roots have been found")
		}
	}
	return cp
}
