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
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/peterbourgon/ff/v3/ffcli"

	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	"github.com/sigstore/cosign/pkg/oci/static"
	ctypes "github.com/sigstore/cosign/pkg/types"
)

var mediaTypes = map[string]types.MediaType{
	"cyclonedx": ctypes.CycloneDXMediaType,
	"spdx":      ctypes.SPDXMediaType,
}

func SBOM() *ffcli.Command {
	var (
		flagset  = flag.NewFlagSet("cosign attach sbom", flag.ExitOnError)
		sbom     = flagset.String("sbom", "", "path to the sbom, or {-} for stdin")
		sbomType = flagset.String("type", "spdx", "type of sbom (spdx|cyclonedx), default spdx")
		regOpts  options.RegistryOpts
	)
	options.ApplyRegistryFlags(&regOpts, flagset)
	return &ffcli.Command{
		Name:       "sbom",
		ShortUsage: "cosign attach sbom <image uri>",
		ShortHelp:  "Attach sbom to the supplied container image",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			if len(args) != 1 {
				return flag.ErrHelp
			}

			mt, ok := mediaTypes[*sbomType]
			if !ok {
				return flag.ErrHelp
			}

			return SBOMCmd(ctx, regOpts, *sbom, mt, args[0])
		},
	}
}

func SBOMCmd(ctx context.Context, regOpts options.RegistryOpts, sbomRef string, sbomType types.MediaType, imageRef string) error {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return err
	}

	b, err := sbomBytes(sbomRef)
	if err != nil {
		return err
	}

	remoteOpts := regOpts.GetRegistryClientOpts(ctx)

	dstRef, err := ociremote.SBOMTag(ref, ociremote.WithRemoteOptions(remoteOpts...))
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Uploading SBOM file for [%s] to [%s] with mediaType [%s].\n", ref.Name(), dstRef.Name(), sbomType)
	img, err := static.NewFile(b, static.WithLayerMediaType(sbomType))
	if err != nil {
		return err
	}
	return remote.Write(dstRef, img, remoteOpts...)
}

func sbomBytes(sbomRef string) ([]byte, error) {
	// sbomRef can be "-", a string or a file.
	switch signatureType(sbomRef) {
	case StdinSignature:
		return ioutil.ReadAll(os.Stdin)
	case RawSignature:
		return []byte(sbomRef), nil
	case FileSignature:
		return ioutil.ReadFile(filepath.Clean(sbomRef))
	default:
		return nil, errors.New("unknown SBOM arg type")
	}
}
