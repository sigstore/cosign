package main

import (
	"context"
	"flag"

	"github.com/peterbourgon/ff/v3/ffcli"
)

func Sign() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign sign", flag.ExitOnError)
		key     = flagset.String("key", "", "path to the private key")
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
			return sign(ctx, *key, args[0])
		},
	}
}

func sign(_ context.Context, keyPath string, imageRef string) error {
	return nil
}
