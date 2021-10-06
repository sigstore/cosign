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
	addPublicKey(cmd)
	addPolicy(cmd)
	addGenerate(cmd)
	addSign(cmd)
	addSignBlob(cmd)
	addGenerateKeyPair(cmd)
	addAttest(cmd)
	addUpload(cmd)
	addDownload(cmd)
	addAttach(cmd)
	addVerify(cmd)
	addVerifyAttestation(cmd)
	addVerifyBlob(cmd)
	addManifest(cmd)
	addDockerfile(cmd)
	addCopy(cmd)
	addClean(cmd)
	addTriangulate(cmd)
	addInitialize(cmd)
	addPIVTool(cmd)
	addVersion(cmd)
	addCompletion(cmd)

	return cmd
}
