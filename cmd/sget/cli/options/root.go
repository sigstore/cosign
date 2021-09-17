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

package options

import (
	"github.com/spf13/cobra"
)

// RootOptions define flags and options for the root sget cli.
type RootOptions struct {
	OutputFile string
	PublicKey  string
	ImageRef   string
}

func AddRootArgs(cmd *cobra.Command, o *RootOptions) {
	cmd.Flags().StringVarP(&o.OutputFile, "output", "o", "",
		"output file")

	cmd.Flags().StringVar(&o.PublicKey, "key", "",
		"path to the public key file, URL, or KMS URI")
}
