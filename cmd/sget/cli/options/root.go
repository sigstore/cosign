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

// Deprecated: This package is deprecated and will be removed in a future release.
package options

import (
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/spf13/cobra"
)

// RootOptions define flags and options for the root sget cli.
type RootOptions struct {
	OutputFile string
	PublicKey  string
	ImageRef   string
	RekorURL   string
}

var _ options.Interface = (*RootOptions)(nil)

// AddFlags implements options.Interface
func (o *RootOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&o.OutputFile, "output", "o", "",
		"output file")

	cmd.Flags().StringVar(&o.PublicKey, "key", "",
		"path to the public key file, URL, or KMS URI")

	cmd.Flags().StringVar(&o.RekorURL, "rekor-url", options.DefaultRekorURL,
		"[EXPERIMENTAL] address of rekor STL server")
}
