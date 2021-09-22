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
	"net/http"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/pkg/errors"

	"github.com/sigstore/cosign/internal/oci"
	"github.com/sigstore/cosign/internal/oci/empty"
	ociremote "github.com/sigstore/cosign/internal/oci/remote"
	"github.com/sigstore/cosign/internal/oci/static"
	"github.com/sigstore/sigstore/pkg/signature"
)

// SignatureImage returns the existing destination image, or a new, empty one.
func SignatureImage(ref name.Reference, opts ...remote.Option) (oci.Signatures, error) {
	base, err := ociremote.Signatures(ref, ociremote.WithRemoteOptions(opts...))
	if err == nil {
		return base, nil
	}
	var te *transport.Error
	if errors.As(err, &te) {
		if te.StatusCode != http.StatusNotFound {
			return nil, te
		}
		return empty.Signatures(), nil
	}
	return nil, err
}

func findDuplicate(sigImage oci.Signatures, newSig oci.Signature, dupeDetector signature.Verifier) ([]byte, error) {
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
		if err := dupeDetector.VerifySignature(bytes.NewReader(uploadedSig), r); err == nil {
			// An equivalent signature has already been uploaded.
			return uploadedSig, nil
		}
	}
	return nil, nil
}

type UploadOpts struct {
	Cert                  []byte
	Chain                 []byte
	DupeDetector          signature.Verifier
	Bundle                *oci.Bundle
	AdditionalAnnotations map[string]string
	RemoteOpts            []remote.Option
	MediaType             string
}

func UploadSignature(signature, payload []byte, dst name.Reference, opts UploadOpts) error {
	b64sig := base64.StdEncoding.EncodeToString(signature)
	var options []static.Option
	// Preserve the default
	if opts.MediaType != "" {
		options = append(options, static.WithMediaType(types.MediaType(opts.MediaType)))
	}
	if opts.Cert != nil {
		options = append(options, static.WithCertChain(opts.Cert, opts.Chain))
	}
	if opts.Bundle != nil {
		options = append(options, static.WithBundle(opts.Bundle))
	}

	l, err := static.NewSignature(payload, b64sig, options...)
	if err != nil {
		return err
	}

	base, err := SignatureImage(dst, opts.RemoteOpts...)
	if err != nil {
		return err
	}

	if opts.DupeDetector != nil {
		if uploadedSig, err := findDuplicate(base, l, opts.DupeDetector); err != nil || uploadedSig != nil {
			return err
		}
	}

	ann, err := l.Annotations()
	if err != nil {
		return err
	}

	img, err := mutate.Append(base, mutate.Addendum{
		Layer:       l,
		Annotations: ann,
	})
	if err != nil {
		return err
	}

	return remote.Write(dst, img, opts.RemoteOpts...)
}
