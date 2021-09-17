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

package cosign

import (
	"context"
	"crypto/x509"
	"runtime"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/pkg/errors"
	"knative.dev/pkg/pool"

	"github.com/sigstore/cosign/internal/oci"
	ociremote "github.com/sigstore/cosign/internal/oci/remote"
)

type SignedPayload struct {
	Base64Signature string
	Payload         []byte
	Cert            *x509.Certificate
	Chain           []*x509.Certificate
	Bundle          *oci.Bundle
	bundleVerified  bool
}

// TODO: marshal the cert correctly.
// func (sp *SignedPayload) MarshalJSON() ([]byte, error) {
// 	x509.Certificate.
// 	pem.EncodeToMemory(&pem.Block{
// 		Type: "CERTIFICATE",
// 		Bytes:
// 	})
// }

const (
	SignatureTagSuffix   = ".sig"
	SBOMTagSuffix        = ".sbom"
	AttestationTagSuffix = ".att"
)

const (
	Signature   = "signature"
	SBOM        = "sbom"
	Attestation = "attestation"
)

func AttachedImageTag(repo name.Repository, digest v1.Hash, tagSuffix string) name.Tag {
	// sha256:d34db33f -> sha256-d34db33f.suffix
	tagStr := strings.ReplaceAll(digest.String(), ":", "-") + tagSuffix
	return repo.Tag(tagStr)
}

func FetchSignaturesForImage(ctx context.Context, signedImgRef name.Reference, sigRepo name.Repository, sigTagSuffix string, registryOpts ...remote.Option) ([]SignedPayload, error) {
	// TODO(mattmoor): If signedImageRef is a digest, this is an unnecessary fetch.
	signedImgDesc, err := remote.Get(signedImgRef, registryOpts...)
	if err != nil {
		return nil, err
	}
	return FetchSignaturesForImageDigest(ctx, signedImgDesc.Descriptor.Digest, sigRepo, sigTagSuffix, registryOpts...)
}

func FetchSignaturesForImageDigest(ctx context.Context, signedImageDigest v1.Hash, sigRepo name.Repository, sigTagSuffix string, registryOpts ...remote.Option) ([]SignedPayload, error) {
	tag := AttachedImageTag(sigRepo, signedImageDigest, sigTagSuffix)

	sigs, err := ociremote.Signatures(tag, registryOpts...)
	if err != nil {
		return nil, errors.Wrap(err, "remote image")
	}
	l, err := sigs.Get()
	if err != nil {
		return nil, errors.Wrap(err, "fetching signatures")
	}

	g := pool.New(runtime.NumCPU())
	signatures := make([]SignedPayload, len(l))
	for i, sig := range l {
		i, sig := i, sig
		g.Go(func() (err error) {
			signatures[i].Payload, err = sig.Payload()
			if err != nil {
				return err
			}
			signatures[i].Base64Signature, err = sig.Base64Signature()
			if err != nil {
				return err
			}
			signatures[i].Cert, err = sig.Cert()
			if err != nil {
				return err
			}
			signatures[i].Chain, err = sig.Chain()
			if err != nil {
				return err
			}
			signatures[i].Bundle, err = sig.Bundle()
			return err
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	return signatures, nil
}
