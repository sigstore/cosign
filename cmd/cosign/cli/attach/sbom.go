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
	"fmt"
	"io/ioutil"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/peterbourgon/ff/v3/ffcli"

	"github.com/sigstore/cosign/cmd/cosign/cli"
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

	h, err := cli.Digest(ctx, ref)
	if err != nil {
		return err
	}

	b, err := ioutil.ReadFile(sbomRef)
	if err != nil {
		return err
	}

	repo := ref.Context()
	dstRef := cosign.AttachedImageTag(repo, h, cosign.SBOMTagSuffix)

	fmt.Fprintf(os.Stderr, "Uploading SBOM file for [%s] to [%s] with mediaType [%s].\n", ref.Name(), dstRef.Name(), sbomType)
	if _, err := cremote.UploadFile(b, dstRef, types.MediaType(sbomType), types.OCIConfigJSON, cli.DefaultRegistryClientOpts(ctx)...); err != nil {
		return err
	}

	return nil
}
