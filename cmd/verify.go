package main

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"github.com/dlorenc/cosign/pkg"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/peterbourgon/ff/v3/ffcli"
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
