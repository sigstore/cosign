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
	"crypto/ed25519"
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
		key         = flagset.String("key", "", "path to the public key")
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
			verified, err := VerifyCmd(ctx, *key, args[0], *checkClaims)
			if err != nil {
				return err
			}
			if !*checkClaims {
				fmt.Fprintln(os.Stderr, "Warning: the following claims have not been verified:")
			}
			for _, vp := range verified {
				fmt.Println(string(vp.Payload))
			}
			return nil
		},
	}
}

func VerifyCmd(_ context.Context, keyRef string, imageRef string, checkClaims bool) ([]cosign.SignedPayload, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, err
	}

	pubKey, err := cosign.LoadPublicKey(keyRef)
	if err != nil {
		return nil, err
	}

	signatures, desc, err := cosign.FetchSignatures(ref)
	if err != nil {
		return nil, err
	}

	// We have a few different checks to do here:
	// 1. The signatures blobs are valid (the public key can verify the payload and signature)
	// 2. The payload blobs are in a format we understand, and the digest of the image is correct

	// 1. First find all valid signatures
	valid, err := validSignatures(pubKey, signatures)
	if err != nil {
		return nil, err
	}

	// If we're not verifying claims, just print and exit.
	if !checkClaims {
		return valid, nil
	}

	// Now we have to actually parse the payloads and make sure the digest is correct
	verified, err := verifyClaims(desc.Digest.Hex, valid)
	if err != nil {
		return nil, err
	}

	return verified, nil
}

func validSignatures(pubKey ed25519.PublicKey, signatures []cosign.SignedPayload) ([]cosign.SignedPayload, error) {
	validSignatures := []cosign.SignedPayload{}
	validationErrs := []string{}

	for _, sp := range signatures {
		if err := cosign.Verify(pubKey, sp.Base64Signature, sp.Payload); err != nil {
			validationErrs = append(validationErrs, err.Error())
			continue
		}
		validSignatures = append(validSignatures, sp)
	}
	// If there are none, we error.
	if len(validSignatures) == 0 {
		return nil, fmt.Errorf("no matching signatures:\n%s", strings.Join(validationErrs, "\n  "))
	}
	return validSignatures, nil

}

func verifyClaims(digest string, signatures []cosign.SignedPayload) ([]cosign.SignedPayload, error) {
	checkClaimErrs := []string{}
	// Now look through the payloads for things we understand
	verifiedPayloads := []cosign.SignedPayload{}
	for _, sp := range signatures {
		ss := cosign.SimpleSigning{}
		if err := json.Unmarshal(sp.Payload, &ss); err != nil {
			checkClaimErrs = append(checkClaimErrs, err.Error())
			continue
		}
		foundDgst := ss.Critical.Image.DockerManifestDigest
		if foundDgst == digest {
			verifiedPayloads = append(verifiedPayloads, sp)
		} else {
			checkClaimErrs = append(checkClaimErrs, fmt.Sprintf("invalid or missing digest in claim: %s", foundDgst))
		}
	}
	if len(verifiedPayloads) == 0 {
		return nil, fmt.Errorf("no matching claims:\n%s", strings.Join(checkClaimErrs, "\n  "))
	}
	return verifiedPayloads, nil
}
