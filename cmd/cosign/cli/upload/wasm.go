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
	"fmt"
	"io/ioutil"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/peterbourgon/ff/v3/ffcli"

	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	cremote "github.com/sigstore/cosign/pkg/cosign/remote"
	"github.com/sigstore/cosign/pkg/types"
)

func Wasm() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign upload wasm", flag.ExitOnError)
		f       = flagset.String("f", "", "path to the wasm file to upload")
		regOpts options.RegistryOpts
	)
	options.ApplyRegistryFlags(&regOpts, flagset)
	return &ffcli.Command{
		Name:       "wasm",
		ShortUsage: "cosign upload wasm -f foo.wasm <image uri>",
		ShortHelp:  "Upload a wasm module to the supplied container image reference",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			if len(args) != 1 {
				return flag.ErrHelp
			}

			return WasmCmd(ctx, regOpts, *f, args[0])
		},
	}
}

func WasmCmd(ctx context.Context, regOpts options.RegistryOpts, wasmPath, imageRef string) error {
	b, err := ioutil.ReadFile(wasmPath)
	if err != nil {
		return err
	}

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Uploading wasm file from [%s] to [%s].\n", wasmPath, ref.Name())
	if _, err := cremote.UploadFile(b, ref, types.WasmLayerMediaType, types.WasmConfigMediaType, regOpts.GetRegistryClientOpts(ctx)...); err != nil {
		return err
	}

	return nil
}
