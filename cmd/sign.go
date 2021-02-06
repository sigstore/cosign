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
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/projectcosign/cosign/pkg"
)

func Sign() *ffcli.Command {
	var (
		flagset     = flag.NewFlagSet("cosign sign", flag.ExitOnError)
		key         = flagset.String("key", "", "path to the private key")
		upload      = flagset.Bool("upload", true, "whether to upload the signature")
		payloadPath = flagset.String("payload", "", "path to a payload file to use rather than generating one.")
	)
	return &ffcli.Command{
		Name:       "sign",
		ShortUsage: "cosign sign -key <key> <image uri>",
		ShortHelp:  "Sign the supplied container image",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			if *key == "" {
				return flag.ErrHelp
			}
			if len(args) != 1 {
				return flag.ErrHelp
			}
			return sign(ctx, *key, args[0], *upload, *payloadPath)
		},
	}
}

func sign(ctx context.Context, keyPath string, imageRef string, upload bool, payloadPath string) error {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return err
	}

	get, err := remote.Get(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return err
	}

	// The payload can be specified via a flag to skip generation.
	var payload []byte
	if payloadPath != "" {
		fmt.Fprintln(os.Stderr, "Using payload from:", payloadPath)
		payload, err = ioutil.ReadFile(payloadPath)
	} else {
		payload, err = pkg.Payload(get.Descriptor)
	}
	if err != nil {
		return err
	}

	pass, err := getPass(false)
	if err != nil {
		return err
	}
	pk, err := pkg.LoadPrivateKey(keyPath, pass)
	if err != nil {
		return err
	}
	signature := ed25519.Sign(pk, payload)

	if !upload {
		fmt.Println(base64.StdEncoding.EncodeToString(signature))
		return nil
	}

	// sha256:... -> sha256-...
	munged := strings.ReplaceAll(get.Descriptor.Digest.String(), ":", "-")
	dstTag := ref.Context().Tag(munged)

	idx, err := pkg.CreateIndex(signature, payload, dstTag)
	if err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr, "Pushing signature to:", dstTag.String())
	if err := remote.WriteIndex(dstTag, idx, remote.WithAuthFromKeychain(authn.DefaultKeychain)); err != nil {
		return err
	}
	return nil
}
