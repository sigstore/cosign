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

// PredicateOptions is the wrapper for predicate related options.
type PredicateOptions struct {
	Path string
	Type string
}

var _ Interface = (*PredicateOptions)(nil)

// AddFlags implements Interface
func (o *PredicateOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.Path, "predicate", "",
		"path to the predicate file.")

	cmd.Flags().StringVar(&o.Type, "type", "custom",
		"specify a predicate type (slsaprovenance|link|spdx|custom) or an URI")
}
