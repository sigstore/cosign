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
	"strings"

	"github.com/pkg/errors"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/pkg/cosign/tuf"
	"github.com/spf13/cobra"
)

func validEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

func addPolicyInit(topLevel *cobra.Command) {
	o := &options.PolicyInitOptions{}

	cmd := &cobra.Command{
		Use:   "policy-init",
		Short: "generate a new keyless policy.",
		Long:  "policy-init is used to generate a root.json policy\nfor keyless signing delegation. This is used to establish a policy for a registry namespace,\na signing threshold and a list of maintainers who can sign over the body section.",
		Example: `
  # extract public key from private key to a specified out file.
  cosign policy-init -ns <project_namespace> --maintainers {email_addresses} --threshold <int> --expires <int>(days)`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var publicKeys []*tuf.Key

			// Process the list of maintainers by
			// 1. Ensure each entry is a correctly formatted email address
			// 2. If 1 is true, then remove surplus whitespace (caused by gaps between commas)
			for _, email := range o.Maintainers {
				if !validEmail(email) {
					panic(fmt.Sprintf("Invalid email format: %s", email))
				} else {
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

			// Current user may sign the body of the root.json and add the signatures.
			/*
					rootMeta, err := root.
					if err != nil {
						return err
					}


				fulcioSigner, err := ctuf.GenerateFulcioSigner(ctx, "")
				if err != nil {
					return err
				}
				rootSig, err := fulcioSigner.Sign(rand.Reader, rootMeta.Signed, crypto.Hash(0))
				if err != nil {
					return errors.Wrap(err, "Error occurred while during artifact signing")
				}
				certStr, _ := json.Marshal(fulcioSigner.Cert())
				for _, id := range fulcioSigner.IDs() {
					if err := r.AddOrUpdateSignature("root.json", data.Signature{
						KeyID:     id,
						Signature: rootSig,
						Cert:      string(certStr)}); err != nil {
						return err
					}
				}

				// Send to rekor
				fmt.Println("Sending policy to transparency log")
				rekorClient, err := rekorClient.GetRekorClient(TlogServer())
				if err != nil {
					return err
				}
				entry, err := cosign.UploadTLog(rekorClient, rootSig, rootMeta.Signed, []byte(fulcioSigner.Cert()))
				if err != nil {
					return err
				}
				fmt.Println("tlog entry created with index:", *entry.LogIndex)

				meta, err := local.GetMeta()
				if err != nil {
					return err
				}
			*/

			policy, err := root.Marshal()
			if err != nil {
				return err
			}
			policyFile, err := policy.JsonMarshal("", "\t")
			if err != nil {
				return err
			}

			if o.OutFile != "" {
				err = ioutil.WriteFile(o.OutFile, policyFile, 0600)
				if err != nil {
					return errors.Wrapf(err, "error writing to root.json")
				}
			}

			/*
				files := []cremote.File{
					{Path: *outFile},
				}

				if err := upload.BlobCmd(ctx, files, "", *imageRef+"/root.json"); err != nil {
					return err
				}
			*/

			return nil
		},
	}

	o.AddFlags(cmd)
	topLevel.AddCommand(cmd)
}
