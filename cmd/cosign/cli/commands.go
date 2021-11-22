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
	"os"

	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/sigstore/cosign/cmd/cosign/cli/options"
)

var (
	ro = &options.RootOptions{}
)

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "cosign",
		DisableAutoGenTag: true,
		SilenceUsage:      true, // Don't show usage on errors
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if ro.OutputFile != "" {
				out, err := os.Create(ro.OutputFile)
				if err != nil {
					return errors.Wrapf(err, "Error creating output file %s", ro.OutputFile)
				}
				stdout := os.Stdout
				defer func() {
					os.Stdout = stdout
					_ = out.Close()
				}()
				os.Stdout = out // TODO: don't do this.
				cmd.SetOut(out)
			}

			if ro.Verbose {
				logs.Debug.SetOutput(os.Stderr)
			}
			return nil
		},
	}
	ro.AddFlags(cmd)

	// Add sub-commands.
	cmd.AddCommand(Attach())
	cmd.AddCommand(Attest())
	cmd.AddCommand(Clean())
	cmd.AddCommand(Completion())
	cmd.AddCommand(Copy())
	cmd.AddCommand(Dockerfile())
	cmd.AddCommand(Download())
	cmd.AddCommand(Generate())
	cmd.AddCommand(GenerateKeyPair())
	cmd.AddCommand(Initialize())
	cmd.AddCommand(Load())
	cmd.AddCommand(Manifest())
	cmd.AddCommand(PIVTool())
	cmd.AddCommand(PKCS11Tool())
	cmd.AddCommand(Policy())
	cmd.AddCommand(PublicKey())
	cmd.AddCommand(Save())
	cmd.AddCommand(Sign())
	cmd.AddCommand(SignBlob())
	cmd.AddCommand(Upload())
	cmd.AddCommand(Verify())
	cmd.AddCommand(VerifyAttestation())
	cmd.AddCommand(VerifyBlob())
	cmd.AddCommand(Triangulate())
	cmd.AddCommand(Version())

	return cmd
}
