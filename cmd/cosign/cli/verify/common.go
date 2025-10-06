// Copyright 2025 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package verify

import (
	"fmt"
	"reflect"

	"github.com/sigstore/cosign/v3/pkg/cosign"
)

// CheckSigstoreBundleUnsupportedOptions checks for incompatible settings on any Verify* command struct when NewBundleFormat is used.
func CheckSigstoreBundleUnsupportedOptions(cmd any, co *cosign.CheckOpts) error {
	if !co.NewBundleFormat {
		return nil
	}
	fieldToErr := map[string]string{
		"CertRef":              "certificate must be in bundle and may not be provided using --certificate",
		"CertChain":            "certificate chain must be in bundle and may not be provided using --certificate-chain",
		"CARoots":              "CA roots/intermediates must be provided using --trusted-root",
		"CAIntermedias":        "CA roots/intermediates must be provided using --trusted-root",
		"TSACertChainPath":     "TSA certificate chain path may only be provided using --trusted-root",
		"RFC3161TimestampPath": "RFC3161 timestamp may not be provided using --rfc3161-timestamp",
		"SigRef":               "signature may not be provided using --signature",
		"SCTRef":               "SCT may not be provided using --sct",
	}
	v := reflect.ValueOf(cmd)
	for f, e := range fieldToErr {
		if field := v.FieldByName(f); field.IsValid() && field.String() != "" {
			return fmt.Errorf("unsupported: %s when using --new-bundle-format", e)
		}
	}
	if co.TrustedMaterial == nil {
		return fmt.Errorf("trusted root is required when using new bundle format")
	}
	return nil
}
