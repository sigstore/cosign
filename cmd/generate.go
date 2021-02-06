package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/dlorenc/cosign/pkg"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/peterbourgon/ff/v3/ffcli"
)

func Generate() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign generate", flag.ExitOnError)
	)
	return &ffcli.Command{
		Name:       "generate",
		ShortUsage: "cosign generate <image uri>",
		ShortHelp:  "generate signatures from the supplied container image",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			if len(args) != 1 {
				return flag.ErrHelp
			}
			return generate(ctx, args[0])
		},
	}
}

func generate(_ context.Context, imageRef string) error {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return err
	}

	get, err := remote.Get(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return err
	}

	payload, err := pkg.Payload(get.Descriptor)
	if err != nil {
		return err
	}
	fmt.Println(string(payload))
	return nil
}
