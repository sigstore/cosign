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
	"bytes"
	"context"
	"encoding/base64"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/cosign/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	"github.com/sigstore/cosign/pkg/oci/static"
	"github.com/sigstore/sigstore/pkg/signature"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
)

type SigningRequest struct {
	SignaturePayload []byte
	SignedEntity     oci.SignedEntity
}

type SigningResults struct {
	SignedPayload []byte
	Signature     []byte
	Cert, Chain   []byte
	Bundle        *oci.Bundle

	OCISignature oci.Signature
	SignedEntity oci.SignedEntity
}

type Signer interface {
	Sign(context.Context, *SigningRequest) (*SigningResults, error)
}

// type NoOpSigner struct{}

// func (NoOpSigner) Sign(_ context.Context, req *SigningRequest) (*SigningResults, error) {
// 	return &SigningResults{
// 		SignedEntity: req.SignedEntity,
// 	}, nil
// }

type PayloadSigner struct {
	PayloadSigner     signature.Signer
	PayloadSignerOpts []signature.SignOption
}

func (ps *PayloadSigner) Sign(ctx context.Context, req *SigningRequest) (*SigningResults, error) {
	opts := []signature.SignOption{signatureoptions.WithContext(ctx)}
	opts = append(opts, ps.PayloadSignerOpts...)
	sig, err := ps.PayloadSigner.SignMessage(bytes.NewReader(req.SignaturePayload), opts...)
	if err != nil {
		return nil, err
	}

	return &SigningResults{
		Signature:    sig,
		SignedEntity: req.SignedEntity,
	}, nil
}

type FulcioSignerWrapper struct {
	Inner Signer

	Cert, Chain []byte
}

func (fs *FulcioSignerWrapper) Sign(ctx context.Context, req *SigningRequest) (*SigningResults, error) {
	results, err := fs.Inner.Sign(ctx, req)
	if err != nil {
		return nil, err
	}

	results.Cert = fs.Cert
	results.Chain = fs.Chain

	return results, nil
}

type RekorSignerWrapper struct {
	Inner Signer

	Bundle *oci.Bundle
}

func (rs *RekorSignerWrapper) Sign(ctx context.Context, req *SigningRequest) (*SigningResults, error) {
	results, err := rs.Inner.Sign(ctx, req)
	if err != nil {
		return nil, err
	}

	results.Bundle = rs.Bundle

	return results, nil
}

type OCISignatureBuilder struct {
	Inner Signer
}

func (sb *OCISignatureBuilder) Sign(ctx context.Context, req *SigningRequest) (*SigningResults, error) {
	results, err := sb.Inner.Sign(ctx, req)
	if err != nil {
		return nil, err
	}

	opts := []static.Option{}
	if results.Cert != nil {
		opts = append(opts, static.WithCertChain(results.Cert, results.Chain))
	}
	if results.Bundle != nil {
		opts = append(opts, static.WithBundle(results.Bundle))
	}
	b64sig := base64.StdEncoding.EncodeToString(results.Signature)

	// Create the new signature for this entity.
	ociSig, err := static.NewSignature(results.SignedPayload, b64sig, opts...)
	if err != nil {
		return nil, err
	}
	results.OCISignature = ociSig

	return results, nil
}

type OCISignatureAttacher struct {
	Inner Signer

	DD mutate.DupeDetector
}

func (sa *OCISignatureAttacher) Sign(ctx context.Context, req *SigningRequest) (*SigningResults, error) {
	results, err := sa.Inner.Sign(ctx, req)
	if err != nil {
		return nil, err
	}

	// Attach the signature to the entity.
	newSE, err := mutate.AttachSignatureToEntity(results.SignedEntity, results.OCISignature, mutate.WithDupeDetector(sa.DD))
	if err != nil {
		return nil, err
	}
	results.SignedEntity = newSE

	return results, nil
}

type RemoteSignerWrapper struct {
	Inner Signer

	SignatureRepo name.Repository
	RegOpts       options.RegistryOptions
}

func (rs *RemoteSignerWrapper) Sign(ctx context.Context, req *SigningRequest) (*SigningResults, error) {
	results, err := rs.Inner.Sign(ctx, req)
	if err != nil {
		return nil, err
	}

	// Publish the signatures associated with this entity
	walkOpts, err := rs.RegOpts.ClientOpts(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "constructing client options")
	}

	// Publish the signatures associated with this entity
	if err := ociremote.WriteSignatures(rs.SignatureRepo, results.SignedEntity, walkOpts...); err != nil {
		return nil, err
	}

	return results, nil
}
