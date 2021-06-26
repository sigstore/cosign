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
	"flag"
	"io/ioutil"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/peterbourgon/ff/v3/ffcli"

	"github.com/sigstore/cosign/pkg/cosign"
	cremote "github.com/sigstore/cosign/pkg/cosign/remote"
)

var mediaTypes = map[string]string{
	"cyclonedx": "application/vnd.cyclonedx",
	"spdx":      "text/spdx",
}

func SBOM() *ffcli.Command {
	var (
		flagset  = flag.NewFlagSet("cosign attach sbom", flag.ExitOnError)
		sbom     = flagset.String("sbom", "", "path to the sbom, or {-} for stdin")
		sbomType = flagset.String("type", "spdx", "type of sbom (spdx|cyclonedx), default spdx")
	)
	return &ffcli.Command{
		Name:       "sbom",
		ShortUsage: "cosign attach sbom <image uri>",
		ShortHelp:  "attach sbom to the supplied container image",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			if len(args) != 1 {
				return flag.ErrHelp
			}

			mt, ok := mediaTypes[*sbomType]
			if !ok {
				return flag.ErrHelp
			}

			return SBOMCmd(ctx, *sbom, mt, args[0])
		},
	}
}

func SBOMCmd(ctx context.Context, sbomRef, sbomType, imageRef string) error {

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return err
	}

	b, err := ioutil.ReadFile(sbomRef)
	if err != nil {
		return err
	}
	s := &cremote.StaticLayer{
		B:  b,
		Mt: types.MediaType(sbomType),
	}

	img := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
	img, err = mutate.Append(img, mutate.Addendum{
		Layer: s,
	})
	if err != nil {
		return err
	}

	// This doesn't work on DockerHub
	m, err := img.Manifest()
	if err != nil {
		return err
	}
	// Setting it to an artifact type doesn't work on media types
	m.Config.MediaType = types.OCIConfigJSON

	auth := remote.WithAuthFromKeychain(authn.DefaultKeychain)

	get, err := remote.Get(ref, auth)
	if err != nil {
		return err
	}
	repo := ref.Context()

	dstRef := cosign.AttachedImageTag(repo, get, cosign.SuffixSBOM)

	if err := remote.Write(dstRef, img, remote.WithAuthFromKeychain(authn.DefaultKeychain)); err != nil {
		return err
	}
	return nil
}
