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

// InitializeOptions is the top level wrapper for the initialize command.
type InitializeOptions struct {
	Mirror    string
	Root      string
	Threshold int
}

var _ Interface = (*InitializeOptions)(nil)

// AddFlags implements Interface
func (o *InitializeOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.Mirror, "mirror", "sigstore-tuf-root",
		"GCS bucket to a SigStore TUF repository or HTTP(S) base URL")

	cmd.Flags().StringVar(&o.Root, "root", "",
		"path to trusted initial root. defaults to embedded root")

	cmd.Flags().IntVar(&o.Threshold, "upload", 3,
		"threshold of root key signers")
}
