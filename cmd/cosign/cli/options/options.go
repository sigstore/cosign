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

import "github.com/spf13/cobra"

type Interface interface {
	// AddFlags adds this options' flags to the cobra command.
	AddFlags(cmd *cobra.Command)
}

var bundleExts = []string{
	"bundle",
}
var certificateExts = []string{
	"cert",
	"crt",
	"pem",
}
var logExts = []string{
	"log",
}
var moduleExts = []string{
	"dll",
	"dylib",
	"so",
}
var privateKeyExts = []string{
	"key",
}
var publicKeyExts = []string{
	"pub",
}
var sbomExts = []string{
	"json",
	"xml",
	"spdx",
}
var signatureExts = []string{
	"sig",
}
var wasmExts = []string{
	"wasm",
}

var rekorEntryTypes = []string{
	"dsse", // first one is the default
	"intoto",
}
