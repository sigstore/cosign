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

// GenerateOptions is the top level wrapper for the generate command.
type GenerateOptions struct {
	AnnotationOptions
	RegistryOpts RegistryOpts
}

// AddGenerateOptions adds the generate command options to cmd.
func AddGenerateOptions(cmd *cobra.Command, o *GenerateOptions) {
	AddAnnotationOptions(cmd, &o.AnnotationOptions)

	cmd.Flags().BoolVar(&o.RegistryOpts.AllowInsecure, "allow-insecure-registry", false,
		"whether to allow insecure connections to registries. Don't use this for anything but testing")
}
