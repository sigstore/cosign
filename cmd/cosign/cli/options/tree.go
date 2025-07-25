// Copyright 2022 The Sigstore Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package options

import "github.com/spf13/cobra"

type TreeOptions struct {
	Registry             RegistryOptions
	RegistryExperimental RegistryExperimentalOptions
	CleanType            string
	ExperimentalOCI11    bool
}

var _ Interface = (*TreeOptions)(nil)

func (c *TreeOptions) AddFlags(cmd *cobra.Command) {
	c.Registry.AddFlags(cmd)
	c.RegistryExperimental.AddFlags(cmd)

	cmd.Flags().BoolVar(&c.ExperimentalOCI11, "experimental-oci11", false,
		"set to true to enable experimental OCI 1.1 behaviour")
}
