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

package remote

import (
	"bytes"
	"encoding/base64"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/cosign/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	"github.com/sigstore/cosign/pkg/oci/static"
	"github.com/sigstore/sigstore/pkg/signature"
)

// NewDupeDetector creates a new DupeDetector that looks for matching signatures that
// can verify the provided signature's payload.
func NewDupeDetector(v signature.Verifier) mutate.DupeDetector {
	return &dd{verifier: v}
}

type dd struct {
	verifier signature.Verifier
}

var _ mutate.DupeDetector = (*dd)(nil)

func (dd *dd) Find(sigImage oci.Signatures, newSig oci.Signature) (oci.Signature, error) {
	newDigest, err := newSig.Digest()
	if err != nil {
		return nil, err
	}
	newMediaType, err := newSig.MediaType()
	if err != nil {
		return nil, err
	}
	newAnnotations, err := newSig.Annotations()
	if err != nil {
		return nil, err
	}

	sigs, err := sigImage.Get()
	if err != nil {
		return nil, err
	}

LayerLoop:
	for _, sig := range sigs {
		existingAnnotations, err := sig.Annotations()
		if err != nil {
			continue LayerLoop
		}

		// if there are any new annotations, then this isn't a duplicate
		for a, value := range newAnnotations {
			if a == static.SignatureAnnotationKey {
				continue // Ignore the signature key, we check it with custom logic below.
			}
			if val, ok := existingAnnotations[a]; !ok || val != value {
				continue LayerLoop
			}
		}
		if existingDigest, err := sig.Digest(); err != nil || existingDigest != newDigest {
			continue LayerLoop
		}
		if existingMediaType, err := sig.MediaType(); err != nil || existingMediaType != newMediaType {
			continue LayerLoop
		}

		existingSignature, err := sig.Base64Signature()
		if err != nil || existingSignature == "" {
			continue LayerLoop
		}
		uploadedSig, err := base64.StdEncoding.DecodeString(existingSignature)
		if err != nil {
			continue LayerLoop
		}
		r, err := newSig.Uncompressed()
		if err != nil {
			return nil, err
		}
		if err := dd.verifier.VerifySignature(bytes.NewReader(uploadedSig), r); err == nil {
			return sig, nil
		}
	}
	return nil, nil
}

type UploadOpts struct {
	DupeDetector       mutate.DupeDetector
	RegistryClientOpts []remote.Option
}

func UploadSignature(l oci.Signature, dst name.Reference, opts UploadOpts) error {
	base, err := ociremote.Signatures(dst, ociremote.WithRemoteOptions(opts.RegistryClientOpts...))
	if err != nil {
		return err
	}

	if opts.DupeDetector != nil {
		if existing, err := opts.DupeDetector.Find(base, l); err != nil || existing != nil {
			return err
		}
	}

	sigs, err := mutate.AppendSignatures(base, l)
	if err != nil {
		return err
	}

	return remote.Write(dst, sigs, opts.RegistryClientOpts...)
}
