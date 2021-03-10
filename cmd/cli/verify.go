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
			if *key == "" && *kmsVal == "" {
				return flag.ErrHelp
			}
			if len(args) != 1 {
				return flag.ErrHelp
			}

			pubKeyDescriptor := *key
			if *kmsVal != "" {
				pubKeyDescriptor = *kmsVal
			}
			pubKey, err := cosign.LoadPublicKey(pubKeyDescriptor)
			if err != nil {
				return errors.Wrap(err, "loading public key")
			}

			co := cosign.CheckOpts{
				Annotations: annotations.annotations,
				Claims:      *checkClaims,
				PubKey:      pubKey,
				Tlog:        os.Getenv("TLOG") == "1",
			}

			verified, err := VerifyCmd(ctx, args[0], co)
			if err != nil {
				return err
			}
			fmt.Fprintln(os.Stderr, "The following checks were performed on these signatures:")
			if co.Claims {
				if co.Annotations != nil {
					fmt.Fprintln(os.Stderr, "  - The specified annotations were verified.")
				}
				fmt.Fprintln(os.Stderr, "  - The cosign claims were validated")
			}
			if co.Tlog {
				fmt.Fprintln(os.Stderr, "  - The claims were present in the transparency log")
			}
			if co.PubKey != nil {
				fmt.Fprintln(os.Stderr, "  - The signatures were verified against the specified public key")
			}
			for _, vp := range verified {
				fmt.Println(string(vp.Payload))
			}
			return nil
		},
	}
}

func VerifyCmd(_ context.Context, imageRef string, co cosign.CheckOpts) ([]cosign.SignedPayload, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, err
	}

	sp, err := cosign.Verify(ref, co)
	if err != nil {
		return nil, err
	}
	return sp, nil
}
