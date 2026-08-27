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
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/v1/types"
	ctypes "github.com/sigstore/cosign/v3/pkg/types"
	"github.com/spf13/cobra"
)

// AttachBundleOptions is the top level wrapper for the attach bundle command.
type AttachBundleOptions struct {
	BundlePaths []string
	Registry    RegistryOptions
}

var _ Interface = (*AttachBundleOptions)(nil)

// AddFlags implements Interface
func (o *AttachBundleOptions) AddFlags(cmd *cobra.Command) {
	o.Registry.AddFlags(cmd)

	cmd.Flags().StringArrayVar(&o.BundlePaths, "bundle", nil,
		"path to bundle to attach")

	cmd.Flags().StringArrayVar(&o.BundlePaths, "payload", nil,
		"path to bundle to attach (deprecated: use --bundle)")
	_ = cmd.Flags().MarkDeprecated("payload", "use --bundle instead")

	cmd.Flags().StringArrayVar(&o.BundlePaths, "attestation", nil,
		"path to bundle to attach (deprecated: use --bundle)")
	_ = cmd.Flags().MarkDeprecated("attestation", "use --bundle instead")
}

// AttachSBOMOptions is the top level wrapper for the attach sbom command.
type AttachSBOMOptions struct {
	SBOM                 string
	SBOMType             string
	SBOMInputFormat      string
	Registry             RegistryOptions
	RegistryExperimental RegistryExperimentalOptions
}

var _ Interface = (*AttachSBOMOptions)(nil)

// AddFlags implements Interface
func (o *AttachSBOMOptions) AddFlags(cmd *cobra.Command) {
	o.Registry.AddFlags(cmd)
	o.RegistryExperimental.AddFlags(cmd)

	cmd.Flags().StringVar(&o.SBOM, "sbom", "",
		"path to the sbom, or {-} for stdin")
	_ = cmd.MarkFlagFilename("sbom", sbomExts...)

	sbomTypes := []string{"spdx", "cyclonedx", "syft"}
	cmd.Flags().StringVar(&o.SBOMType, "type", sbomTypes[0],
		"type of sbom ("+strings.Join(sbomTypes, "|")+")")
	_ = cmd.RegisterFlagCompletionFunc("type", cobra.FixedCompletions(sbomTypes, cobra.ShellCompDirectiveNoFileComp))

	inputFormats := []string{ctypes.JSONInputFormat, ctypes.XMLInputFormat, ctypes.TextInputFormat}
	cmd.Flags().StringVar(&o.SBOMInputFormat, "input-format", "",
		"type of sbom input format ("+strings.Join(inputFormats, "|")+")")
	_ = cmd.RegisterFlagCompletionFunc("input-format", cobra.FixedCompletions(inputFormats, cobra.ShellCompDirectiveNoFileComp))
}

func (o *AttachSBOMOptions) MediaType() (types.MediaType, error) {
	var looksLikeJSON bool
	if strings.HasSuffix(o.SBOM, ".json") {
		looksLikeJSON = true
	}
	switch o.SBOMType {
	case "cyclonedx":
		if o.SBOMInputFormat != "" && o.SBOMInputFormat != ctypes.XMLInputFormat && o.SBOMInputFormat != ctypes.JSONInputFormat {
			return "invalid", fmt.Errorf("invalid SBOM input format: %q, expected (json|xml)", o.SBOMInputFormat)
		}
		if o.SBOMInputFormat == ctypes.JSONInputFormat || looksLikeJSON {
			return ctypes.CycloneDXJSONMediaType, nil
		}
		return ctypes.CycloneDXXMLMediaType, nil

	case "spdx":
		if o.SBOMInputFormat != "" && o.SBOMInputFormat != ctypes.TextInputFormat && o.SBOMInputFormat != ctypes.JSONInputFormat {
			return "invalid", fmt.Errorf("invalid SBOM input format: %q, expected (json|text)", o.SBOMInputFormat)
		}
		if o.SBOMInputFormat == ctypes.JSONInputFormat || looksLikeJSON {
			return ctypes.SPDXJSONMediaType, nil
		}
		return ctypes.SPDXMediaType, nil
	case "syft":
		if o.SBOMInputFormat != "" && o.SBOMInputFormat != ctypes.JSONInputFormat {
			return "invalid", fmt.Errorf("invalid SBOM input format: %q, expected (json)", o.SBOMInputFormat)
		}
		return ctypes.SyftMediaType, nil
	default:
		return "unknown", fmt.Errorf("unknown SBOM type: %q, expected (spdx|cyclonedx|syft)", o.SBOMType)
	}
}
