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
	"time"

	"github.com/spf13/cobra"
)

// RootOptions define flags and options for the root cosign cli.
type RootOptions struct {
	OutputFile string
	Verbose    bool
	Timeout    time.Duration
}

// DefaultTimeout specifies the default timeout for commands.
const DefaultTimeout = 3 * time.Minute

var _ Interface = (*RootOptions)(nil)

// AddFlags implements Interface
func (o *RootOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&o.OutputFile, "output-file", "",
		"log output to a file")
	_ = cmd.Flags().SetAnnotation("output-file", cobra.BashCompFilenameExt, []string{})

	cmd.PersistentFlags().BoolVarP(&o.Verbose, "verbose", "d", false,
		"log debug output")

	cmd.PersistentFlags().DurationVarP(&o.Timeout, "timeout", "t", DefaultTimeout,
		"timeout for commands")
}
