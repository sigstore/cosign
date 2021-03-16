/*
Copyright The Rekor Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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

func Verify() *ffcli.Command {
	var (
		flagset     = flag.NewFlagSet("cosign verify", flag.ExitOnError)
		kmsVal      = flagset.String("kms", "", "verify via a public key stored in a KMS")
		key         = flagset.String("key", "", "path to the public key")
		checkClaims = flagset.Bool("check-claims", true, "whether to check the claims found")
		annotations = annotationsMap{}
	)
	flagset.Var(&annotations, "a", "extra key=value pairs to sign")

	return &ffcli.Command{
		Name:       "verify",
		ShortUsage: "cosign verify -key <key> <image uri>",
		ShortHelp:  "Verify a signature on the supplied container image",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			if len(args) != 1 {
				return flag.ErrHelp
			}

			co := cosign.CheckOpts{
				Annotations: annotations.annotations,
				Claims:      *checkClaims,
				Tlog:        cosign.Experimental(),
				Roots:       fulcio.Roots,
			}
			// Keys are optional!
			if *key != "" {
				pubKeyDescriptor := *key
				if *kmsVal != "" {
					pubKeyDescriptor = *kmsVal
				}
				pubKey, err := cosign.LoadPublicKey(pubKeyDescriptor)
				if err != nil {
					return errors.Wrap(err, "loading public key")
				}
				co.PubKey = pubKey
			}

			verified, err := VerifyCmd(ctx, args[0], co)
			if err != nil {
				return err
			}
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
			if co.Roots != nil { // This is always true for now, we hardcode the fulcio root.
				fmt.Fprintln(os.Stderr, "  - Any certificates were verified against the Fulcio roots.")
				if !co.Tlog {
					fmt.Fprintln(os.Stderr, "  - WARNING - THE CERTIFICATE EXPIRY WAS NOT CHECKED. set COSIGN_EXPERIMENTAL=1 to check!")
				}
			}
			for _, vp := range verified {
				if vp.Cert != nil {
					fmt.Println("Certificate common name: ", vp.Cert.Subject.CommonName)
				}
				fmt.Println(string(vp.Payload))
			}
			return nil
		},
	}
}

func VerifyCmd(ctx context.Context, imageRef string, co cosign.CheckOpts) ([]cosign.SignedPayload, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, err
	}

	sp, err := cosign.Verify(ctx, ref, co)
	if err != nil {
		return nil, err
	}
	return sp, nil
}
