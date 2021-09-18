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
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/cosign/internal/oci"
)

const (
	sigkey    = "dev.cosignproject.cosign/signature"
	certkey   = "dev.sigstore.cosign/certificate"
	chainkey  = "dev.sigstore.cosign/chain"
	BundleKey = "dev.sigstore.cosign/bundle"
)

// These enable mocking for unit testing without faking an entire registry.
var (
	remoteImage = remote.Image
	remoteIndex = remote.Index
	remoteGet   = remote.Get
)

// SignedEntity provides access to a remote reference, and its signatures.
// The SignedEntity will be one of SignedImage or SignedImageIndex.
func SignedEntity(ref name.Reference, options ...Option) (oci.SignedEntity, error) {
	o, err := makeOptions(ref.Context(), options...)
	if err != nil {
		return nil, err
	}

	got, err := remoteGet(ref, o.ROpt...)
	if err != nil {
		return nil, err
	}

	switch got.MediaType {
	case types.OCIImageIndex, types.DockerManifestList:
		ii, err := got.ImageIndex()
		if err != nil {
			return nil, err
		}
		return &index{
			v1Index: ii,
			ref:     ref.Context().Digest(got.Digest.String()),
			opt:     o,
		}, nil

	case types.OCIManifestSchema1, types.DockerManifestSchema2:
		i, err := got.Image()
		if err != nil {
			return nil, err
		}
		return &image{
			Image: i,
			opt:   o,
		}, nil

	default:
		return nil, fmt.Errorf("unknown mime type: %v", got.MediaType)
	}
}

func normalize(h v1.Hash, suffix string) string {
	// sha256:d34db33f -> sha256-d34db33f.suffix
	return strings.ReplaceAll(h.String(), ":", "-") + suffix
}

// signatures is a shared implementation of the oci.Signed* Signatures method.
func signatures(digestable interface{ Digest() (v1.Hash, error) }, o *options) (oci.Signatures, error) {
	h, err := digestable.Digest()
	if err != nil {
		return nil, err
	}
	return Signatures(o.TargetRepository.Tag(normalize(h, o.SignatureSuffix)), o.OriginalOptions...)
}
