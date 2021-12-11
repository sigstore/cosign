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
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/cmd/sget/cli/options"
	"github.com/sigstore/cosign/pkg/sget"
	"github.com/spf13/cobra"
)

var (
	bo = &options.BlobOptions{}
)

func Blob() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "blob [--signature <signature uri] <artifact uri>",
		Short: "download a blob and verify its signature [EXPERIMENTAL]",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return errors.New("an artifact uri is required")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			wc, err := createSink(ro.OutputFile)
			if err != nil {
				return err
			}
			defer wc.Close()
			return sget.New(ro.PublicKey, wc, ro.RekorURL).GetBlob(cmd.Context(), bo.Signature, args[0])
		},
	}

	bo.AddFlags(cmd)
	return cmd
}
