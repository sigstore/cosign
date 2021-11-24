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
	"encoding/base64"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/cosign/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	"github.com/sigstore/cosign/pkg/oci/static"
)

type SigningResults struct {
	SignedDigest name.Digest
	OCISignature oci.Signature

	Info map[string]interface{}
}

type Signer interface {
	Sign(context.Context, oci.SignedEntity) (*SigningResults, error)
}

type StaticSigner struct {
	Digest      name.Digest
	Payload     []byte
	Signature   []byte
	Cert, Chain []byte
	Bundle      *oci.Bundle

	DD      mutate.DupeDetector
	RegOpts options.RegistryOptions
}

func (ls *StaticSigner) Sign(ctx context.Context, se oci.SignedEntity) (*SigningResults, error) {
	opts := []static.Option{}
	if ls.Cert != nil {
		opts = append(opts, static.WithCertChain(ls.Cert, ls.Chain))
	}
	if ls.Bundle != nil {
		opts = append(opts, static.WithBundle(ls.Bundle))
	}
	b64sig := base64.StdEncoding.EncodeToString(ls.Signature)

	// Create the new signature for this entity.
	sig, err := static.NewSignature(ls.Payload, b64sig, opts...)
	if err != nil {
		return nil, err
	}

	// Attach the signature to the entity.
	newSE, err := mutate.AttachSignatureToEntity(se, sig, mutate.WithDupeDetector(ls.DD))
	if err != nil {
		return nil, err
	}

	// Publish the signatures associated with this entity
	walkOpts, err := ls.RegOpts.ClientOpts(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "constructing client options")
	}

	// Publish the signatures associated with this entity
	if err := ociremote.WriteSignatures(ls.Digest.Repository, newSE, walkOpts...); err != nil {
		return nil, err
	}

	return &SigningResults{
		SignedDigest: ls.Digest,
		OCISignature: sig,
		Info:         map[string]interface{}{},
	}, nil
}
