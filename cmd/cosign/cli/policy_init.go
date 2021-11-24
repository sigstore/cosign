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
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/cmd/cosign/cli/upload"
	rekorClient "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/sigstore/pkg/cryptoutils"

	"github.com/sigstore/cosign/pkg/cosign"
	cremote "github.com/sigstore/cosign/pkg/cosign/remote"
	"github.com/sigstore/cosign/pkg/cosign/tuf"
	"github.com/sigstore/cosign/pkg/sget"
	sigs "github.com/sigstore/cosign/pkg/signature"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
	"github.com/spf13/cobra"
)

func validEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

func rootPath(imageRef string) string {
	return filepath.Join(imageRef, "root")
}

func Policy() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "subcommand to manage a keyless policy.",
		Long:  "policy is used to manage a root.json policy\nfor keyless signing delegation. This is used to establish a policy for a registry namespace,\na signing threshold and a list of maintainers who can sign over the body section.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(
		initPolicy(),
		signPolicy(),
	)

	return cmd
}

func initPolicy() *cobra.Command {
	o := &options.PolicyInitOptions{}

	cmd := &cobra.Command{
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
					// Currently only a single issuer can be set for all the maintainers.
					key := tuf.FulcioVerificationKey(strings.TrimSpace(email), o.Issuer)
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

			if o.Expires > 0 {
				root.Expires = time.Now().AddDate(0, 0, o.Expires).UTC().Round(time.Second)
			}

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
				err = os.WriteFile(o.OutFile, policyFile, 0600)
				if err != nil {
					return errors.Wrapf(err, "error writing to %s", outfile)
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

			return upload.BlobCmd(cmd.Context(), o.Registry, files, "", rootPath(o.ImageRef))
		},
	}

	o.AddFlags(cmd)

	return cmd
}

func signPolicy() *cobra.Command {
	o := &options.PolicySignOptions{}

	cmd := &cobra.Command{
		Use:   "sign",
		Short: "sign a keyless policy.",
		Long:  "policy is used to manage a root.json policy\nfor keyless signing delegation. This is used to establish a policy for a registry namespace,\na signing threshold and a list of maintainers who can sign over the body section.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if o.Timeout != 0 {
				var cancelFn context.CancelFunc
				ctx, cancelFn = context.WithTimeout(ctx, o.Timeout)
				defer cancelFn()
			}

			// Get Fulcio signer
			sv, err := sign.SignerFromKeyOpts(ctx, "", sign.KeyOpts{
				FulcioURL:                o.Fulcio.URL,
				IDToken:                  o.Fulcio.IdentityToken,
				InsecureSkipFulcioVerify: o.Fulcio.InsecureSkipFulcioVerify,
				RekorURL:                 o.Rekor.URL,
				OIDCIssuer:               o.OIDC.Issuer,
				OIDCClientID:             o.OIDC.ClientID,
				OIDCClientSecret:         o.OIDC.ClientSecret,
			})
			if err != nil {
				return err
			}
			defer sv.Close()

			certs, err := cryptoutils.LoadCertificatesFromPEM(bytes.NewReader(sv.Cert))
			if err != nil {
				return err
			}
			if len(certs) == 0 || certs[0].EmailAddresses == nil {
				return errors.New("error decoding certificate")
			}
			signerEmail := sigs.CertSubject(certs[0])
			signerIssuer := sigs.CertIssuerExtension(certs[0])

			// Retrieve root.json from registry.
			imgName := rootPath(o.ImageRef)
			ref, err := name.ParseReference(imgName)
			if err != nil {
				return err
			}
			opts := []remote.Option{
				remote.WithAuthFromKeychain(authn.DefaultKeychain),
				remote.WithContext(ctx),
			}

			img, err := remote.Image(ref, opts...)
			if err != nil {
				return err
			}
			dgst, err := img.Digest()
			if err != nil {
				return err
			}

			result := &bytes.Buffer{}
			if err := sget.New(imgName+"@"+dgst.String(), "", result).Do(ctx); err != nil {
				return errors.Wrap(err, "error getting result")
			}
			b, err := io.ReadAll(result)
			if err != nil {
				return errors.Wrap(err, "error reading bytes from root.json")
			}

			// Unmarshal policy and verify that Fulcio signer email is in the trusted
			signed := &tuf.Signed{}
			if err := json.Unmarshal(b, signed); err != nil {
				return errors.Wrap(err, "unmarshalling signed root policy")
			}

			// Create and add signature
			key := tuf.FulcioVerificationKey(signerEmail, signerIssuer)
			sig, err := sv.SignMessage(bytes.NewReader(signed.Signed), signatureoptions.WithContext(ctx))
			if err != nil {
				return errors.Wrap(err, "error occurred while during artifact signing")
			}
			signature := tuf.Signature{
				Signature: base64.StdEncoding.EncodeToString(sig),
				Cert:      base64.StdEncoding.EncodeToString(sv.Cert),
			}
			if err := signed.AddOrUpdateSignature(key, signature); err != nil {
				return err
			}

			// Upload to rekor
			if options.EnableExperimental() {
				// TODO: Refactor with sign.go
				rekorBytes := sv.Cert
				rekorClient, err := rekorClient.GetRekorClient(o.Rekor.URL)
				if err != nil {
					return err
				}
				entry, err := cosign.TLogUpload(ctx, rekorClient, sig, signed.Signed, rekorBytes)
				if err != nil {
					return err
				}
				fmt.Fprintln(os.Stderr, "tlog entry created with index:", *entry.LogIndex)
			}

			// Push updated root.json to the registry
			policyFile, err := signed.JSONMarshal("", "\t")
			if err != nil {
				return err
			}

			var outfile string
			if o.OutFile != "" {
				outfile = o.OutFile
				err = os.WriteFile(o.OutFile, policyFile, 0600)
				if err != nil {
					return errors.Wrapf(err, "error writing to %s", outfile)
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

			return upload.BlobCmd(ctx, o.Registry, files, "", rootPath(o.ImageRef))
		},
	}

	o.AddFlags(cmd)

	return cmd
}
