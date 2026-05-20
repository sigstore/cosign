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

import (
	"github.com/spf13/cobra"
)

// UpdateKeyPairOptions is the top level wrapper for the update-key-pair command.
type UpdateKeyPairOptions struct {
	// Key is the path to the existing encrypted private key file.
	Key string
}

var _ Interface = (*UpdateKeyPairOptions)(nil)

// AddFlags implements Interface
func (o *UpdateKeyPairOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&o.Key, "key", "k", "",
		"path to the private key file to update the password for")
	_ = cmd.MarkFlagFilename("key", privateKeyExts...)
	_ = cmd.MarkFlagRequired("key")
}
