package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/dlorenc/cosign/pkg"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/peterbourgon/ff/v3/ffcli"
)

func Upload() *ffcli.Command {
	var (
		flagset   = flag.NewFlagSet("cosign upload", flag.ExitOnError)
		signature = flagset.String("signature", "", "path to the signature or {-} for stdin")
	)
	return &ffcli.Command{
		Name:       "upload",
		ShortUsage: "cosign upload <image uri>",
		ShortHelp:  "upload signatures from the supplied container image",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			if len(args) != 1 {
				return flag.ErrHelp
			}
			return upload(ctx, *signature, args[0])
		},
	}
}

func upload(ctx context.Context, sigRef, imageRef string) error {
	var b64SigBytes []byte
	var err error

	// This can be "-", a file or a string.
	if sigRef == "-" {
		b64SigBytes, err = ioutil.ReadAll(os.Stdin)
	} else if _, err := os.Stat(sigRef); os.IsNotExist(err) {
		b64SigBytes = []byte(sigRef)
	} else {
		b64SigBytes, err = ioutil.ReadFile(sigRef)
	}
	if err != nil {
		return err
	}
	if len(b64SigBytes) == 0 {
		return errors.New("empty signature")
	}

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return err
	}

	get, err := remote.Get(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return err
	}
	// sha256:... -> sha256-...
	munged := strings.ReplaceAll(get.Descriptor.Digest.String(), ":", "-")
	dstTag := ref.Context().Tag(munged)

	payload, err := pkg.Payload(get.Descriptor)
	if err != nil {
		return err
	}

	// This expects it to not be base64 encoded, so decode first
	sigBytes, err := base64.StdEncoding.DecodeString(string(b64SigBytes))
	if err != nil {
		return err
	}
	idx, err := pkg.CreateIndex(sigBytes, payload, dstTag)
	if err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr, "Pushing signature to:", dstTag.String())
	if err := remote.WriteIndex(dstTag, idx, remote.WithAuthFromKeychain(authn.DefaultKeychain)); err != nil {
		return err
	}
	return nil
}
