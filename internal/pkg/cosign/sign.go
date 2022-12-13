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

package cosign

import (
	"context"
	"crypto"
	"io"

	"github.com/sigstore/cosign/v2/pkg/oci"
)

// Signer signs payloads in the form of `oci.Signature`s
type Signer interface {
	// Sign signs the given payload, returning the results as an `oci.Signature` which can be verified using the returned `crypto.PublicKey`.
	Sign(ctx context.Context, payload io.Reader) (oci.Signature, crypto.PublicKey, error)
}
