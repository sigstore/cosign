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

package cli

import (
	"context"
	"flag"
	"fmt"

	"github.com/sigstore/cosign/cmd/cosign/cli/triangulate"

	"os"

	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/sigstore/cosign/cmd/cosign/cli/attach"
	"github.com/sigstore/cosign/cmd/cosign/cli/attest"
	"github.com/sigstore/cosign/cmd/cosign/cli/copy"
	"github.com/sigstore/cosign/cmd/cosign/cli/dockerfile"
	"github.com/sigstore/cosign/cmd/cosign/cli/download"
	"github.com/sigstore/cosign/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/cmd/cosign/cli/initialize"
	"github.com/sigstore/cosign/cmd/cosign/cli/manifest"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/pivcli"
	"github.com/sigstore/cosign/cmd/cosign/cli/publickey"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/cmd/cosign/cli/upload"
	"github.com/sigstore/cosign/cmd/cosign/cli/verify"
)

var (
	ro = &options.RootOptions{}
)

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use: "cosign",
		RunE: func(cmd *cobra.Command, args []string) error {
			root := &ffcli.Command{
				ShortUsage: "cosign [flags] <subcommand>",
				Subcommands: []*ffcli.Command{
					// Key Management
					publickey.PublicKey(),
					generate.GenerateKeyPair(),
					// Signing
					sign.Sign(),
					sign.SignBlob(),
					attest.Attest(),
					generate.Generate(),
					verify.Verify(),
					verify.VerifyAttestation(),
					verify.VerifyBlob(),
					// Manifest sub-tree
					manifest.Manifest(),
					// Upload sub-tree
					upload.Upload(),
					// Download sub-tree
					download.Download(),
					// Attach sub-tree
					attach.Attach(),
					// Dockerfile sub-tree
					dockerfile.Dockerfile(),
					// PIV sub-tree
					pivcli.PivKey(),
					// PIV sub-tree
					copy.Copy(),
					Clean(),
					triangulate.Triangulate(),
					// Initialize
					initialize.Initialize(),
					// Version
					Version()},
				Exec: func(context.Context, []string) error {
					return flag.ErrHelp
				},
			}

			if err := root.Parse(args); err != nil {
				printErrAndExit(err)
			}

			if ro.OutputFile != "" {
				out, err := os.Create(ro.OutputFile)
				if err != nil {
					fmt.Fprintf(os.Stderr, "error: %v\n", errors.Wrapf(err, "Error creating output file %s", ro.OutputFile))
					os.Exit(1)
				}
				stdout := os.Stdout
				defer func() {
					os.Stdout = stdout
					out.Close()
				}()
				os.Stdout = out
			}

			if ro.Verbose {
				logs.Debug.SetOutput(os.Stderr)
			}

			if err := root.Run(context.Background()); err != nil {
				printErrAndExit(err)
			}
			return nil // TODO: use cobra to output help.
		},
	}
	ro.AddFlags(cmd)

	// Add sub-commands.
	addPublicKey(cmd)
	addGenerate(cmd)
	addSign(cmd)
	addSignBlob(cmd)
	addGenerateKeyPair(cmd)
	addAttest(cmd)
	addUpload(cmd)
	addCopy(cmd)
	addClean(cmd)
	addTriangulate(cmd)
	addInitialize(cmd)
	addPIVTool(cmd)
	addVersion(cmd)

	return cmd
}

func printErrAndExit(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
