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
	"crypto/ecdsa"
	"flag"
	"fmt"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/tlog"
)

func Verify() *ffcli.Command {
	var (
		flagset     = flag.NewFlagSet("cosign verify", flag.ExitOnError)
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
			if *key == "" {
				return flag.ErrHelp
			}
			if len(args) != 1 {
				return flag.ErrHelp
			}

			pubKey, err := cosign.LoadPublicKey(*key)
			if err != nil {
				return flag.ErrHelp
			}

			verified, err := VerifyCmd(ctx, pubKey, args[0], *checkClaims, annotations.annotations)
			if err != nil {
				return err
			}
			if !*checkClaims {
				fmt.Fprintln(os.Stderr, "Warning: the following claims have not been verified:")
			}
			if os.Getenv(tlog.Env) == "1" {
				fmt.Fprintln(os.Stderr, "The following signatures were all present in the transparency log:")
			}
			for _, vp := range verified {
				fmt.Println(string(vp.Payload))
			}
			return nil
		},
	}
}

func VerifyCmd(_ context.Context, pubKey *ecdsa.PublicKey, imageRef string, checkClaims bool, annotations map[string]string) ([]cosign.SignedPayload, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, err
	}

	sp, err := cosign.Verify(ref, pubKey, checkClaims, annotations)
	if err != nil {
		return nil, err
	}
	if os.Getenv(tlog.Env) != "1" {
		return sp, nil
	}
	tlogPayloads, err := tlog.Verify(sp, pubKey)
	if err != nil {
		return nil, err
	}
	return tlogPayloads, nil
}
