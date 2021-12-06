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
	"os"
	"os/exec"
	"strings"

	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/verify"
	"github.com/spf13/cobra"
)

func Helm() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "helm",
		Short: "Provides utilities for discovering images in and performing operations on Helm Charts",
	}

	cmd.AddCommand(
		helmChartVerify(),
	)

	return cmd
}

type HelmChartVerifyCommand struct {
	verify.VerifyCommand
	Path string
}

func (h *HelmChartVerifyCommand) Exec(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return flag.ErrHelp
	}

	cmd := fmt.Sprintf(`helm template %s | grep "image:" | awk -F" " '{print $2}' | sed 's/^"//g' | sed 's/\"//g' | sort | awk '!seen[$0]++'`, args[0])

	images, err := exec.Command("sh", "-c", cmd).Output()

	fmt.Fprintf(os.Stderr, "Found images are: %v", string(images))

	if err != nil {
		return err
	}

	i := strings.Split(string(images), "\n")
	return h.VerifyCommand.Exec(ctx, i[:len(i)-1])
}

func helmChartVerify() *cobra.Command {
	o := &options.HelmOptions{}

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "verify container images managed by Helm Chart",
		Long:  "Allows you to sign container images managed by Helm Chart",
		Example: `
`,

		RunE: func(cmd *cobra.Command, args []string) error {
			annotations, err := o.AnnotationsMap()
			if err != nil {
				return err
			}

			v := HelmChartVerifyCommand{
				VerifyCommand: verify.VerifyCommand{
					RegistryOptions: o.Registry,
					CheckClaims:     o.CheckClaims,
					KeyRef:          o.Key,
					CertEmail:       o.CertEmail,
					Sk:              o.SecurityKey.Use,
					Slot:            o.SecurityKey.Slot,
					Output:          o.Output,
					RekorURL:        o.Rekor.URL,
					Attachment:      o.Attachment,
					Annotations:     annotations,
				},
			}

			return v.Exec(cmd.Context(), args)
		},
	}

	o.AddFlags(cmd)
	return cmd
}
