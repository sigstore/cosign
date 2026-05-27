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

package cli

import (
	tufv1 "github.com/sigstore/sigstore/pkg/tuf"
	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	var rootCmd = &cobra.Command{
		Use:               "cosign-lite",
		Short:             "cosign-lite is a lightweight Sigstore signing and verification utility",
		DisableAutoGenTag: true,
	}
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	rootCmd.AddCommand(
		Initialize(),
	)

	return rootCmd
}

func Initialize() *cobra.Command {
	var mirror string
	var rootPath string
	var rootChecksum string
	var staging bool

	cmd := &cobra.Command{
		Use:   "initialize",
		Short: "Initialize TUF roots of trust",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			switch {
			case staging:
				return doInitializeStaging(ctx)
			case rootChecksum != "":
				return doInitializeWithRootChecksum(ctx, rootPath, mirror, rootChecksum)
			default:
				return doInitialize(ctx, rootPath, mirror)
			}
		},
	}

	cmd.Flags().StringVar(&mirror, "mirror", tufv1.DefaultRemoteRoot, "GCS bucket to a SigStore TUF repository, or HTTP(S) base URL, or file:/// for local filestore remote (air-gap)")
	cmd.Flags().StringVar(&rootPath, "root", "", "path to trusted initial root. defaults to embedded root")
	cmd.Flags().StringVar(&rootChecksum, "root-checksum", "", "checksum of the initial root, required if root is downloaded via http(s). expects sha256 by default, can be changed to sha512 by providing sha512:<checksum>")
	cmd.Flags().BoolVar(&staging, "staging", false, "use the staging TUF repository")

	return cmd
}
