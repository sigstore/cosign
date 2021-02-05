package main

import (
	"context"
	"flag"

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
	return nil
}
