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
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/pkg/errors"

	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/fulcio"
	"github.com/sigstore/cosign/pkg/cosign/pivkey"
	"github.com/sigstore/sigstore/pkg/signature/payload"
)

// VerifyCommand verifies a signature on a supplied container image
type VerifyCommand struct {
	CheckClaims bool
	KeyRef      string
	Sk          bool
	Output      string
	Annotations *map[string]interface{}
}

// Verify builds and returns an ffcli command
func Verify() *ffcli.Command {
	cmd := VerifyCommand{}
	flagset := flag.NewFlagSet("cosign verify", flag.ExitOnError)
	annotations := annotationsMap{}

	flagset.StringVar(&cmd.KeyRef, "key", "", "path to the public key file, URL, or KMS URI")
	flagset.BoolVar(&cmd.Sk, "sk", false, "whether to use a hardware security key")

	flagset.BoolVar(&cmd.CheckClaims, "check-claims", true, "whether to check the claims found")
	flagset.StringVar(&cmd.Output, "output", "json", "output the signing image information. Default JSON.")

	// parse annotations
	flagset.Var(&annotations, "a", "extra key=value pairs to sign")
	cmd.Annotations = &annotations.annotations

	return &ffcli.Command{
		Name:       "verify",
		ShortUsage: "cosign verify -key <key path>|<key url>|<kms uri> <image uri>",
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
  cosign verify -key cosign.pub <IMAGE>

  # verify image with public key provided by URL
  cosign verify -key https://host.for/<FILE> <IMAGE>

  # verify image with public key stored in Google Cloud KMS
  cosign verify -key gcpkms://projects/<PROJECT>/locations/global/keyRings/<KEYRING>/cryptoKeys/<KEY> <IMAGE>`,
		FlagSet: flagset,
		Exec:    cmd.Exec,
	}
}

// Exec runs the verification command
func (c *VerifyCommand) Exec(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return flag.ErrHelp
	}

	if !oneOf(c.KeyRef, c.Sk) && !EnableExperimental() {
		return &KeyParseError{}
	}

	co := &cosign.CheckOpts{
		Annotations: *c.Annotations,
		Claims:      c.CheckClaims,
		Tlog:        EnableExperimental(),
		Roots:       fulcio.Roots,
	}
	keyRef := c.KeyRef

	// Keys are optional!
	if keyRef != "" {
		pubKey, err := publicKeyFromKeyRef(ctx, keyRef)
		if err != nil {
			return errors.Wrap(err, "loading public key")
		}
		co.PubKey = pubKey
	} else if c.Sk {
		pubKey, err := pivkey.NewPublicKeyProvider()
		if err != nil {
			return errors.Wrap(err, "loading public key")
		}
		co.PubKey = pubKey
	}

	for _, imageRef := range args {
		ref, err := name.ParseReference(imageRef)
		if err != nil {
			return err
		}

		verified, err := cosign.Verify(ctx, ref, co, TlogServer())
		if err != nil {
			return err
		}

		PrintVerification(imageRef, verified, co, "text")
	}

	return nil
}

// PrintVerification logs details about the verification to stdout
func PrintVerification(imgRef string, verified []cosign.SignedPayload, co *cosign.CheckOpts, output string) {
	fmt.Fprintf(os.Stderr, "\nVerification for %s --\n", imgRef)
	fmt.Fprintln(os.Stderr, "The following checks were performed on each of these signatures:")
	if co.Claims {
		if co.Annotations != nil {
			fmt.Fprintln(os.Stderr, "  - The specified annotations were verified.")
		}
		fmt.Fprintln(os.Stderr, "  - The cosign claims were validated")
	}
	if co.VerifyBundle {
		fmt.Fprintln(os.Stderr, "  - Existence of the claims in the transparency log was verified offline")
	} else if co.Tlog {
		fmt.Fprintln(os.Stderr, "  - The claims were present in the transparency log")
		fmt.Fprintln(os.Stderr, "  - The signatures were integrated into the transparency log when the certificate was valid")
	}
	if co.PubKey != nil {
		fmt.Fprintln(os.Stderr, "  - The signatures were verified against the specified public key")
	}
	fmt.Fprintln(os.Stderr, "  - Any certificates were verified against the Fulcio roots.")

	switch output {
	case "text":
		for _, vp := range verified {
			if vp.Cert != nil {
				fmt.Println("Certificate subject: ", vp.Cert.EmailAddresses)
			}

			fmt.Println(string(vp.Payload))
		}
	default:
		var outputKeys []payload.SimpleContainerImage
		for _, vp := range verified {
			ss := payload.SimpleContainerImage{}
			err := json.Unmarshal(vp.Payload, &ss)
			if err != nil {
				fmt.Println("error decoding the payload:", err.Error())
				return
			}

			if vp.Cert != nil {
				if ss.Optional == nil {
					ss.Optional = make(map[string]interface{})
				}
				ss.Optional["Subject"] = vp.Cert.EmailAddresses
			}
			if vp.Bundle != nil {
				if ss.Optional == nil {
					ss.Optional = make(map[string]interface{})
				}
				ss.Optional["Bundle"] = vp.Bundle
			}

			outputKeys = append(outputKeys, ss)
		}

		b, err := json.Marshal(outputKeys)
		if err != nil {
			fmt.Println("error when generating the output:", err.Error())
			return
		}

		fmt.Printf("\n%s\n", string(b))
	}
}
