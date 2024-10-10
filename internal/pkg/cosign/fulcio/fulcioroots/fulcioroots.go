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
	"crypto/x509"
	"sync"

	"github.com/sigstore/cosign/v2/pkg/cosign"
)

var (
	rootsOnce        sync.Once
	roots            *x509.CertPool
	intermediates    *x509.CertPool
	singletonRootErr error
)

// Get returns the Fulcio root certificate.
//
// If the SIGSTORE_ROOT_FILE environment variable is set, the root config found
// there will be used instead of the normal Fulcio roots.
func Get() (*x509.CertPool, error) {
	rootsOnce.Do(func() {
		roots, intermediates, singletonRootErr = initRoots()
	})
	return roots, singletonRootErr
}

// GetIntermediates returns the Fulcio intermediate certificates.
//
// If the SIGSTORE_ROOT_FILE environment variable is set, the root config found
// there will be used instead of the normal Fulcio intermediates.
func GetIntermediates() (*x509.CertPool, error) {
	rootsOnce.Do(func() {
		roots, intermediates, singletonRootErr = initRoots()
	})
	return intermediates, singletonRootErr
}

// ReInit reinitializes the global roots and intermediates, overriding the sync.Once lock.
// This is only to be used for tests, where the trust root environment variables may change after the roots are initialized in the module.
func ReInit() error {
	roots, intermediates, singletonRootErr = initRoots()
	return singletonRootErr
}

func initRoots() (*x509.CertPool, *x509.CertPool, error) {
	return cosign.GetFulcioCerts()
}
