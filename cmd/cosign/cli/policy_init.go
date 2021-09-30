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
	"fmt"
	"io/ioutil"
	"net/mail"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/upload"
	cremote "github.com/sigstore/cosign/pkg/cosign/remote"
	"github.com/sigstore/cosign/pkg/cosign/tuf"
	"github.com/spf13/cobra"
)

func validEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

func addPolicy(topLevel *cobra.Command) {
	o := &options.PolicyInitOptions{}

	policyCmd := &cobra.Command{
		Use:   "policy",
		Short: "subcommand to manage a keyless policy.",
		Long:  "policy is used to manage a root.json policy\nfor keyless signing delegation. This is used to establish a policy for a registry namespace,\na signing threshold and a list of maintainers who can sign over the body section.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	initCmd := &cobra.Command{
		Use:   "init",
		Short: "generate a new keyless policy.",
		Long:  "init is used to generate a root.json policy\nfor keyless signing delegation. This is used to establish a policy for a registry namespace,\na signing threshold and a list of maintainers who can sign over the body section.",
		Example: `
  # extract public key from private key to a specified out file.
  cosign policy init -ns <project_namespace> --maintainers {email_addresses} --threshold <int> --expires <int>(days)`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var publicKeys []*tuf.Key

			// Process the list of maintainers by
			// 1. Ensure each entry is a correctly formatted email address
			// 2. If 1 is true, then remove surplus whitespace (caused by gaps between commas)
			for _, email := range o.Maintainers {
				if !validEmail(email) {
					panic(fmt.Sprintf("Invalid email format: %s", email))
				} else {
					// Currently no issuer is set: this would need to be set by the initializer.
					key := tuf.FulcioVerificationKey(strings.TrimSpace(email), "")
					publicKeys = append(publicKeys, key)
				}
			}

			// Create a new root.
			root := tuf.NewRoot()

			// Add the maintainer identities to the root's trusted keys.
			for _, key := range publicKeys {
				root.AddKey(key)
			}

			// Set root keys, threshold, and namespace.
			role, ok := root.Roles["root"]
			if !ok {
				role = &tuf.Role{KeyIDs: []string{}, Threshold: 1}
			}
			role.AddKeysWithThreshold(publicKeys, o.Threshold)
			root.Roles["root"] = role
			root.Namespace = o.ImageRef

			policy, err := root.Marshal()
			if err != nil {
				return err
			}
			policyFile, err := policy.JSONMarshal("", "\t")
			if err != nil {
				return err
			}

			var outfile string
			if o.OutFile != "" {
				outfile = o.OutFile
				err = ioutil.WriteFile(o.OutFile, policyFile, 0600)
				if err != nil {
					return errors.Wrapf(err, "error writing to root.json")
				}
			} else {
				tempFile, err := os.CreateTemp("", "root")
				if err != nil {
					return err
				}
				outfile = tempFile.Name()
				defer os.Remove(tempFile.Name())
			}

			files := []cremote.File{
				cremote.FileFromFlag(outfile),
			}

			return upload.BlobCmd(cmd.Context(), options.RegistryOptions{}, files, "", o.ImageRef+"/root.json")
		},
	}

	o.AddFlags(initCmd)
	policyCmd.AddCommand(initCmd)
	topLevel.AddCommand(policyCmd)
}
