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

// DSSEAttestor creates attestations in the form of `oci.Signature`s
type DSSEAttestor interface {
	// Attest creates an attestation, in the form of an `oci.Signature`, from the given payload.
	// The signature and payload are stored as a DSSE envelope in `osi.Signature.Payload()`
	DSSEAttest(ctx context.Context, payload io.Reader) (oci.Signature, crypto.PublicKey, error)
}
