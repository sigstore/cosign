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

import (
	"errors"

	"github.com/spf13/cobra"
)

type CleanType string

const (
	CleanTypeSignature   CleanType = "signature"
	CleanTypeAttestation CleanType = "attestation"
	CleanTypeSbom        CleanType = "sbom"
	CleanTypeAll         CleanType = "all"
)

func defaultCleanType() CleanType {
	return CleanTypeAll
}

// cleanType implements github.com/spf13/pflag.Value.
func (c *CleanType) String() string {
	return string(*c)
}

// cleanType implements github.com/spf13/pflag.Value.
func (c *CleanType) Set(v string) error {
	switch v {
	case "signature", "attestation", "sbom", "all":
		*c = CleanType(v)
		return nil
	default:
		return errors.New(`must be one of "signature", "attestation", "sbom", or "all"`)
	}
}

// cleanType implements github.com/spf13/pflag.Value.
func (c *CleanType) Type() string {
	return "CLEAN_TYPE"
}

type CleanOptions struct {
	Registry  RegistryOptions
	CleanType CleanType
	Force     bool
}

var _ Interface = (*CleanOptions)(nil)

func (c *CleanOptions) AddFlags(cmd *cobra.Command) {
	c.Registry.AddFlags(cmd)
	c.CleanType = defaultCleanType()
	cmd.Flags().Var(&c.CleanType, "type", "a type of clean: <signature|attestation|sbom|all>")
	// TODO(#2044): Rename to --skip-confirmation for consistency?
	cmd.Flags().BoolVarP(&c.Force, "force", "f", false, "do not prompt for confirmation")
}
