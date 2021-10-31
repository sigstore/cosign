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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	"github.com/sigstore/cosign/pkg/oci/static"
)

func SBOMCmd(ctx context.Context, regOpts options.RegistryOptions, sbomRef string, sbomType types.MediaType, imageRef string) error {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return err
	}

	b, err := sbomBytes(sbomRef)
	if err != nil {
		return err
	}

	remoteOpts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		return err
	}

	dstRef, err := ociremote.SBOMTag(ref, remoteOpts...)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Uploading SBOM file for [%s] to [%s] with mediaType [%s].\n", ref.Name(), dstRef.Name(), sbomType)
	img, err := static.NewFile(b, static.WithLayerMediaType(sbomType))
	if err != nil {
		return err
	}
	return remote.Write(dstRef, img, regOpts.GetRegistryClientOpts(ctx)...)
}

func sbomBytes(sbomRef string) ([]byte, error) {
	// sbomRef can be "-", a string or a file.
	switch signatureType(sbomRef) {
	case StdinSignature:
		return io.ReadAll(os.Stdin)
	case RawSignature:
		return []byte(sbomRef), nil
	case FileSignature:
		return os.ReadFile(filepath.Clean(sbomRef))
	default:
		return nil, errors.New("unknown SBOM arg type")
	}
}
