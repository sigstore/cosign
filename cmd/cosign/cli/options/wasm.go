//
// Copyright 2026 The Sigstore Authors.
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

import "github.com/spf13/cobra"

type WasmStripSignaturesOptions struct {
	Output string
}

type WasmListSignaturesOptions struct {
	Output string
}

var _ Interface = (*WasmStripSignaturesOptions)(nil)
var _ Interface = (*WasmListSignaturesOptions)(nil)

func (o *WasmStripSignaturesOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&o.Output, "output", "o", "",
		"write the unsigned WebAssembly module to FILE")
	_ = cmd.MarkFlagFilename("output", wasmExts...)
	_ = cmd.MarkFlagRequired("output")
}

func (o *WasmListSignaturesOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&o.Output, "output", "o", "text",
		"output format for embedded signatures (json|text)")
}
