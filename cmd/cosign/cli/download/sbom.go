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

package download

import (
	"context"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/sigstore/cosign/cmd/cosign/cli"
	"github.com/sigstore/cosign/pkg/cosign"
)

func SBOM() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign download sbom", flag.ExitOnError)
	)
	return &ffcli.Command{
		Name:       "sbom",
		ShortUsage: "cosign download sbom <image uri>",
		ShortHelp:  "Download SBOMs from the supplied container image",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			if len(args) != 1 {
				return flag.ErrHelp
			}
			_, err := SBOMCmd(ctx, args[0], os.Stdout)
			return err
		},
	}
}

func SBOMCmd(ctx context.Context, imageRef string, out io.Writer) ([]string, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, err
	}

	h, err := cli.Digest(ctx, ref)
	if err != nil {
		return nil, err
	}

	repo := ref.Context()
	dstRef := cosign.AttachedImageTag(repo, h, cosign.SBOMTagSuffix)
	img, err := remote.Image(dstRef, cli.DefaultRegistryClientOpts(ctx)...)
	if err != nil {
		return nil, err
	}
	layers, err := img.Layers()
	if err != nil {
		return nil, err
	}
	sboms := []string{}
	for _, l := range layers {
		mt, err := l.MediaType()
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(os.Stderr, "Found SBOM of media type: %s\n", mt)
		r, err := l.Compressed()
		if err != nil {
			return nil, err
		}
		sbom, err := ioutil.ReadAll(r)
		if err != nil {
			return nil, err
		}
		sboms = append(sboms, string(sbom))
		fmt.Fprintln(out, string(sbom))
	}
	return sboms, nil
}
