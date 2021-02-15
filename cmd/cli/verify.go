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

package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/projectcosign/cosign/pkg/cosign"
)

func Verify() *ffcli.Command {
	var (
		flagset     = flag.NewFlagSet("cosign verify", flag.ExitOnError)
		key         = flagset.String("key", "", "path to the private key")
		checkClaims = flagset.Bool("check-claims", true, "whether to check the claims found")
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
			return VerifyCmd(ctx, *key, args[0], *checkClaims)
		},
	}
}

func VerifyCmd(_ context.Context, keyRef string, imageRef string, checkClaims bool) error {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return err
	}

	pubKey, err := cosign.LoadPublicKey(keyRef)
	if err != nil {
		return err
	}

	signatures, desc, err := cosign.FetchSignatures(ref)
	if err != nil {
		return err
	}

	verifyErrs := []string{}
	verifiedPayloads := [][]byte{}
	for _, sp := range signatures {
		if err := cosign.Verify(pubKey, sp.Base64Signature, sp.Payload); err != nil {
			verifyErrs = append(verifyErrs, err.Error())
			continue
		}
		verifiedPayloads = append(verifiedPayloads, sp.Payload)
	}
	if len(verifiedPayloads) == 0 {
		return fmt.Errorf("no matching signatures:\n%s", strings.Join(verifyErrs, "\n  "))
	}

	if !checkClaims {
		fmt.Fprintln(os.Stderr, "Warning: the following claims have not been verified:")
		for _, vp := range verifiedPayloads {
			fmt.Println(string(vp))
		}
		return nil
	}

	checkClaimErrs := []string{}
	foundOne := false
	// Now look through the payloads for things we understand
	for _, vp := range verifiedPayloads {
		ss := cosign.SimpleSigning{}
		if err := json.Unmarshal(vp, &ss); err != nil {
			checkClaimErrs = append(checkClaimErrs, err.Error())
			continue
		}
		foundDgst := ss.Critical.Image.DockerManifestDigest
		if foundDgst == desc.Digest.Hex {
			foundOne = true
			fmt.Println(string(vp))
		} else {
			checkClaimErrs = append(checkClaimErrs, fmt.Sprintf("invalid or missing digest in claim: %s", foundDgst))
			continue
		}
	}
	if !foundOne {
		return fmt.Errorf("no matching claims:\n%s", strings.Join(checkClaimErrs, "\n  "))
	}

	return nil
}
