// Copyright 2022 The Sigstore Authors.
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

// TimestampAuthorityOptions is the struct for timestamp authority related options.
type TimestampAuthorityOptions struct {
	TSAServerURL                 string
	TimestampCertChainPath       string
	InsecureSkipTSResponseVerify bool
}

var _ Interface = (*TimestampAuthorityOptions)(nil)

// AddFlags implements Interface
func (o *TimestampAuthorityOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.TSAServerURL, "timestamp-server-url", "",
		"url to the Timestamp RFC3161 server, default none")

	cmd.Flags().StringVar(&o.TimestampCertChainPath, "timestamp-certificate-chain", "",
		"path to PEM-encoded certificate chain file for the RFC3161 timestamp authority. Must contain the root CA certificate. "+
			"Optionally may contain intermediate CA certificates, and may contain the leaf TSA certificate if not present in the timestamp")

	cmd.Flags().BoolVar(&o.InsecureSkipTSResponseVerify, "insecure-skip-ts-verify", false,
		"skip verifying timestamp response on signing")
}
