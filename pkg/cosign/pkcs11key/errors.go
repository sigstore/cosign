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

package pkcs11key

import (
	"errors"
	"fmt"
)

var (
	ContextNotInitialized error = errors.New("context not initialized")
	SignerNotSet          error = errors.New("signer not set")
	CertNotSet            error = errors.New("certificate not set")
)

// errSignerNotFound reports that no PKCS11 key pair matched the given id/label.
func errSignerNotFound(keyID, keyLabel []byte) error {
	return fmt.Errorf("%w: no key pair found for id=%q label=%q in slot/token", SignerNotSet, keyID, keyLabel)
}
