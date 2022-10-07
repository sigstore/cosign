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

package cli

import (
	"flag"

	"github.com/spf13/cobra"

	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/upload"
)

func Upload() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "upload",
		Short: "Provides utilities for uploading artifacts to a registry",
	}

	cmd.AddCommand(
		uploadBlob(),
		uploadWASM(),
	)

	return cmd
}

func uploadBlob() *cobra.Command {
	o := &options.UploadBlobOptions{}

	cmd := &cobra.Command{
		Use:   "blob",
		Short: "Upload one or more blobs to the supplied container image address.",
		Example: `  cosign upload blob -f <blob ref> <image uri>

  # upload a blob named foo to the location specified by <IMAGE>
  cosign upload blob -f foo <IMAGE>

  # upload a blob named foo to the location specified by <IMAGE>, setting the os field to "MYOS".
  cosign upload blob -f foo:MYOS <IMAGE>

  # upload a blob named foo to the location specified by <IMAGE>, setting the os field to "MYOS" and the platform field to "MYPLATFORM".
  cosign upload blob -f foo:MYOS/MYPLATFORM <IMAGE>

  # upload two blobs named foo-darwin and foo-linux to the location specified by <IMAGE>, setting the os fields
  cosign upload blob -f foo-darwin:darwin -f foo-linux:linux <IMAGE>

  # upload a blob named foo to the location specified by <IMAGE>, setting annotations mykey=myvalue.
  cosign upload blob -a mykey=myvalue -f foo <IMAGE>

  # upload two blobs named foo-darwin and foo-linux to the location specified by <IMAGE>, setting annotations
  cosign upload blob -a mykey=myvalue -a myotherkey="my other value" -f foo-darwin:darwin -f foo-linux:linux <IMAGE>`,
		Args: cobra.ExactArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(o.Files.Files) < 1 {
				return flag.ErrHelp
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			files, err := o.Files.Parse()
			if err != nil {
				return err
			}

			return upload.BlobCmd(cmd.Context(), o.Registry, files, o.Annotations, o.ContentType, args[0])
		},
	}

	o.AddFlags(cmd)

	return cmd
}

func uploadWASM() *cobra.Command {
	o := &options.UploadWASMOptions{}

	cmd := &cobra.Command{
		Use:     "wasm",
		Short:   "Upload a wasm module to the supplied container image reference",
		Example: "  cosign upload wasm -f foo.wasm <image uri>",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return upload.WasmCmd(cmd.Context(), o.Registry, o.File, args[0])
		},
	}

	o.AddFlags(cmd)

	return cmd
}
