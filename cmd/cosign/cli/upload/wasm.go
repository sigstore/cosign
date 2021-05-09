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

package upload

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
	cremote "github.com/sigstore/cosign/pkg/cosign/remote"
)

func Wasm() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign upload wasm", flag.ExitOnError)
		f       = flagset.String("f", "", "path to the wasm file to upload")
	)
	return &ffcli.Command{
		Name:       "wasm",
		ShortUsage: "cosign upload wasm -f foo.wasm <image uri>",
		ShortHelp:  "upload a wasm module to the supplied container image reference",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			if len(args) != 1 {
				return flag.ErrHelp
			}

			return WasmCmd(ctx, *f, args[0])
		},
	}
}

func WasmCmd(ctx context.Context, wasmPath, imageRef string) error {

	img := mutate.MediaType(empty.Image, types.OCIManifestSchema1)

	b, err := ioutil.ReadFile(wasmPath)
	if err != nil {
		return err
	}
	s := &cremote.StaticLayer{
		B:  b,
		Mt: types.MediaType("application/vnd.wasm.content.layer.v1+wasm"),
	}

	img, err = mutate.Append(img, mutate.Addendum{
		Layer: s,
	})
	if err != nil {
		return err
	}

	m, err := img.Manifest()
	if err != nil {
		return err
	}
	m.Config.MediaType = "application/vnd.wasm.config.v1+json"

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return err
	}
	if err := remote.Write(ref, img, remote.WithAuthFromKeychain(authn.DefaultKeychain)); err != nil {
		return err
	}
	return nil
}
