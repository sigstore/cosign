/*
Copyright The Cosign Authors.

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

package main

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/projectcosign/cosign/pkg"
)

func Verify() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign verify", flag.ExitOnError)
		key     = flagset.String("key", "", "path to the private key")
	)
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
			return verify(ctx, *key, args[0])
		},
	}
}

func verify(_ context.Context, keyRef string, imageRef string) error {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return err
	}

	pubKey, err := pkg.LoadPublicKey(keyRef)
	if err != nil {
		return err
	}

	signatures, err := pkg.FetchSignatures(ref)
	if err != nil {
		return err
	}

	errs := []string{}
	verified := false
	for _, sp := range signatures {
		if err := pkg.Verify(pubKey, sp.Base64Signature, sp.Payload); err != nil {
			errs = append(errs, err.Error())
			continue
		}
		fmt.Println(string(sp.Payload))
		verified = true
	}
	if !verified {
		return fmt.Errorf("no matching signatures:\n%s", strings.Join(errs, "\n  "))
	}
	return nil
}
