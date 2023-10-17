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

package attach

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v2/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
)

func SignatureCmd(ctx context.Context, regOpts options.RegistryOptions, sigRef, payloadRef, certRef, certChainRef, timeStampedSigRef, rekorBundleRef, imageRef string) error {
	b64SigBytes, err := signatureBytes(sigRef)
	if err != nil {
		return err
	} else if len(b64SigBytes) == 0 {
		return errors.New("empty signature")
	}

	ref, err := name.ParseReference(imageRef, regOpts.NameOptions()...)
	if err != nil {
		return err
	}
	ociremoteOpts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		return err
	}
	digest, err := ociremote.ResolveDigest(ref, ociremoteOpts...)
	if err != nil {
		return err
	}
	// Overwrite "ref" with a digest to avoid a race where we use a tag
	// multiple times, and it potentially points to different things at
	// each access.
	ref = digest // nolint

	var payload []byte
	if payloadRef == "" {
		payload, err = cosign.ObsoletePayload(ctx, digest)
	} else {
		payload, err = os.ReadFile(filepath.Clean(payloadRef))
	}
	if err != nil {
		return err
	}

	sig, err := static.NewSignature(payload, string(b64SigBytes))
	if err != nil {
		return err
	}

	var cert []byte
	var certChain []byte
	var timeStampedSig []byte
	var rekorBundle *bundle.RekorBundle

	if certRef != "" {
		cert, err = os.ReadFile(filepath.Clean(certRef))
		if err != nil {
			return err
		}
	}

	if certChainRef != "" {
		certChain, err = os.ReadFile(filepath.Clean(certChainRef))
		if err != nil {
			return err
		}
	}

	if timeStampedSigRef != "" {
		timeStampedSig, err = os.ReadFile(filepath.Clean(timeStampedSigRef))
		if err != nil {
			return err
		}
	}
	tsBundle := bundle.TimestampToRFC3161Timestamp(timeStampedSig)

	if rekorBundleRef != "" {
		rekorBundleByte, err := os.ReadFile(filepath.Clean(rekorBundleRef))
		if err != nil {
			return err
		}

		var localCosignPayload cosign.LocalSignedPayload
		err = json.Unmarshal(rekorBundleByte, &localCosignPayload)
		if err != nil {
			return err
		}

		rekorBundle = localCosignPayload.Bundle
	}

	newSig, err := mutate.Signature(sig, mutate.WithCertChain(cert, certChain), mutate.WithRFC3161Timestamp(tsBundle), mutate.WithBundle(rekorBundle))
	if err != nil {
		return err
	}

	se, err := ociremote.SignedEntity(digest, ociremoteOpts...)
	if err != nil {
		return err
	}

	// Attach the signature to the entity.
	newSE, err := mutate.AttachSignatureToEntity(se, newSig)
	if err != nil {
		return err
	}

	// Publish the signatures associated with this entity
	return ociremote.WriteSignatures(digest.Repository, newSE, ociremoteOpts...)
}

type SignatureArgType uint8

const (
	StdinSignature SignatureArgType = iota
	RawSignature   SignatureArgType = iota
	FileSignature  SignatureArgType = iota
)

func signatureBytes(sigRef string) ([]byte, error) {
	// sigRef can be "-", a string or a file.
	switch signatureType(sigRef) {
	case StdinSignature:
		return io.ReadAll(os.Stdin)
	case RawSignature:
		return []byte(sigRef), nil
	case FileSignature:
		return os.ReadFile(filepath.Clean(sigRef))
	default:
		return nil, errors.New("unknown signature arg type")
	}
}

func signatureType(sigRef string) SignatureArgType {
	switch {
	case sigRef == "-":
		return StdinSignature
	default:
		return FileSignature
	}
}
