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
	"fmt"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	"github.com/sigstore/cosign/v2/pkg/types"
)

func WasmCmd(ctx context.Context, regOpts options.RegistryOptions, wasmPath, imageRef string) error {
	b, err := os.ReadFile(wasmPath)
	if err != nil {
		return err
	}

	ref, err := name.ParseReference(imageRef, regOpts.NameOptions()...)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Uploading wasm file from [%s] to [%s].\n", wasmPath, ref.Name())
	img, err := static.NewFile(b, static.WithLayerMediaType(types.WasmLayerMediaType), static.WithConfigMediaType(types.WasmConfigMediaType))
	if err != nil {
		return err
	}
	return remote.Write(ref, img, regOpts.GetRegistryClientOpts(ctx)...)
}
