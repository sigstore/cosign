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
	"crypto"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/mail"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/cmd/cosign/cli/upload"
	"github.com/sigstore/cosign/pkg/cosign"
	cremote "github.com/sigstore/cosign/pkg/cosign/remote"
	ctuf "github.com/sigstore/cosign/pkg/cosign/tuf"
	rekorClient "github.com/sigstore/rekor/pkg/client"

	"github.com/theupdateframework/go-tuf"
	"github.com/theupdateframework/go-tuf/data"
)

func validEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

func PolicyInit() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign policy-init", flag.ExitOnError)

		imageRef    = flagset.String("ns", "", "The registry namespace")
		mainTainers = flagset.String("maintainers", "", "Comma separated list of maintainers")
		threshHold  = flagset.Int("threshold", 2, "Threshold")
		outFile     = flagset.String("out", "root.json", "Output policy locally")
	)

	return &ffcli.Command{
		Name:       "policy-init",
		ShortUsage: "generate a new keyless policy",
		ShortHelp:  "policy-init is used to generate a TUF style root.json policy for keyless signing delegation",
		LongHelp: `policy-init is used to generate a root.json policy
for keyless signing delegation. This is used to establish a policy for a registry namespace,
a signing threshold and a list of maintainers who can sign over the body section.
EXAMPLES
  # extract public key from private key to a specified out file.
  cosign policy-init -ns <project_namespace> --maintainers {email_addresses} --threshold <int> --expires <int>(days)`,
		FlagSet: flagset,
		Exec: func(ctx context.Context, args []string) error {
			var emailList []string

			// Process the list of maintainers by
			// 1. Ensure each entry is a correctly formatted email address
			// 2. If 1 is true, then remove surplus whitespace (caused by gaps between commas)
			emails := strings.Split(*mainTainers, ",")
			for _, email := range emails {
				if !validEmail(email) {
					panic(fmt.Sprintf("Invalid email format: %s", email))
				} else {
					emailList = append(emailList, email)
					// strip out whitespace if there is any
					for i := range emailList {
						emailList[i] = strings.TrimSpace(emailList[i])
					}
				}
			}

			// Create a TUF root.json with the threshold and expiration.
			// TODO: For later events, we will need to pull the existing metadata from the registry.
			local := tuf.MemoryStore(make(map[string]json.RawMessage), nil)
			r, err := tuf.NewRepo(local)
			if err != nil {
				return err
			}

			// Add the maintainer identities to the root and targets role.
			for _, email := range emailList {
				identity := ctuf.FulcioVerificationKey(email)
				if err := r.AddVerificationKey("root", identity); err != nil {
					return err
				}
			}
			// TODO: Can we set a RegistryNamespace anywhere? In the targets metadata? Do we need it in the signed payload?
			if err := r.SetThreshold("root", *threshHold); err != nil {
				return err
			}

			// Current user may sign the body of the root.json and add the signatures.
			rootMeta, err := r.SignedMeta("root.json")
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
				if err := r.AppendSignature("root.json", data.Signature{
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

			if *outFile != "" {
				err = ioutil.WriteFile(*outFile, meta["root.json"], 0600)
				if err != nil {
					return errors.Wrapf(err, "error writing to root.json")
				}
			}

			files := []cremote.File{
				{Path: *outFile},
			}

			if err := upload.BlobCmd(ctx, files, "", *imageRef+"/root.json"); err != nil {
				return err
			}

			return nil
		},
	}
}
