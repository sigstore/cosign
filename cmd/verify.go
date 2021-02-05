package main

import (
	"context"
	"flag"

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

func verify(_ context.Context, keyPath string, imageRef string) error {
	return nil
}
