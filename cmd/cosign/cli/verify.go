// Copyright 2021 The Rekor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
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

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/pkg/errors"

	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/fulcio"
)

// VerifyCommand verifies a signature on a supplied container image
type VerifyCommand struct {
	KmsVal      string
	Key         string
	CheckClaims bool
	Annotations *map[string]string
}

// Verify builds and returns an ffcli command
func Verify() *ffcli.Command {
	cmd := VerifyCommand{}
	flagset := flag.NewFlagSet("cosign verify", flag.ExitOnError)
	annotations := annotationsMap{}

	flagset.StringVar(&cmd.Key, "key", "", "path to the public key")
	flagset.StringVar(&cmd.KmsVal, "kms", "", "verify via a public key stored in a KMS")
	flagset.BoolVar(&cmd.CheckClaims, "check-claims", true, "whether to check the claims found")

	// parse annotations
	flagset.Var(&annotations, "a", "extra key=value pairs to sign")
	cmd.Annotations = &annotations.annotations

	return &ffcli.Command{
		Name:       "verify",
		ShortUsage: "cosign verify -key <key>|-kms <kms> <image uri>",
		ShortHelp:  "Verify a signature on the supplied container image",
		LongHelp: `Verify signature and annotations on an image by checking the claims
against the transparency log.

EXAMPLES
  # verify cosign claims and signing certificates on the image
  cosign verify <IMAGE>

  # additionally verify specified annotations
  cosign verify -a key1=val1 -a key2=val2 <IMAGE>

  # (experimental) additionally, verify with the transparency log
  COSIGN_EXPERIMENTAL=1 cosign verify <IMAGE>

  # verify image with public key
  cosign verify -key <FILE> <IMAGE>

  # verify image with public key stored in Google Cloud KMS
  cosign verify -kms  gcpkms://projects/<PROJECT>/locations/global/keyRings/<KEYRING>/cryptoKeys/<KEY> <IMAGE>`,
		FlagSet: flagset,
		Exec:    cmd.Exec,
	}
}

// Exec runs the verification command
func (c *VerifyCommand) Exec(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return flag.ErrHelp
	}
	if c.Key != "" && c.KmsVal != "" {
		return &KeyParseError{}
	}

	co := cosign.CheckOpts{
		Annotations: *c.Annotations,
		Claims:      c.CheckClaims,
		Tlog:        cosign.Experimental(),
		Roots:       fulcio.Roots,
	}
	// Keys are optional!
	if c.Key != "" {
		pubKeyDescriptor := c.Key
		if c.KmsVal != "" {
			pubKeyDescriptor = c.KmsVal
		}
		pubKey, err := cosign.LoadPublicKey(pubKeyDescriptor)
		if err != nil {
			return errors.Wrap(err, "loading public key")
		}
		co.PubKey = pubKey
	}

	imageRef := args[0]

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return err
	}

	verified, err := cosign.Verify(ctx, ref, co)
	if err != nil {
		return err
	}

	printVerification(verified, co)
	return nil
}

// printVerification logs details about the verification to stdout
func printVerification(verified []cosign.SignedPayload, co cosign.CheckOpts) {
	fmt.Fprintln(os.Stderr, "The following checks were performed on each of these signatures:")
	if co.Claims {
		if co.Annotations != nil {
			fmt.Fprintln(os.Stderr, "  - The specified annotations were verified.")
		}
		fmt.Fprintln(os.Stderr, "  - The cosign claims were validated")
	}
	if co.Tlog {
		fmt.Fprintln(os.Stderr, "  - The claims were present in the transparency log")
		fmt.Fprintln(os.Stderr, "  - The signatures were integrated into the transparency log when the certificate was valid")
	}
	if co.PubKey != nil {
		fmt.Fprintln(os.Stderr, "  - The signatures were verified against the specified public key")
	}
	fmt.Fprintln(os.Stderr, "  - Any certificates were verified against the Fulcio roots.")

	for _, vp := range verified {
		if vp.Cert != nil {
			fmt.Println("Certificate common name: ", vp.Cert.Subject.CommonName)
		}
		fmt.Println(string(vp.Payload))
	}
}
