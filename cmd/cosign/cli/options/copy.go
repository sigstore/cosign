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

// CopyOptions is the top level wrapper for the copy command.
type CopyOptions struct {
	CopyOnly      string
	SignatureOnly bool
	Force         bool
	Platform      string
	Registry      RegistryOptions
}

var _ Interface = (*CopyOptions)(nil)

// AddFlags implements Interface
func (o *CopyOptions) AddFlags(cmd *cobra.Command) {
	o.Registry.AddFlags(cmd)

	cmd.Flags().StringVar(&o.CopyOnly, "only", "",
		"custom string array to only copy specific items, this flag is comma delimited. ex: --only=sbom,sign,att")

	cmd.Flags().BoolVar(&o.SignatureOnly, "sig-only", false,
		"[DEPRECATED] only copy the image signature")

	cmd.Flags().BoolVarP(&o.Force, "force", "f", false,
		"overwrite destination image(s), if necessary")

	cmd.Flags().StringVar(&o.Platform, "platform", "",
		"only copy container image and its signatures for a specific platform image")
}
