package main

import (
	"context"
	"flag"

	"github.com/peterbourgon/ff/v3/ffcli"
)

func Download() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign download", flag.ExitOnError)
	)
	return &ffcli.Command{
		Name:       "download",
		ShortUsage: "cosign download <image uri>",
		ShortHelp:  "Download signatures from the supplied container image",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			if len(args) != 1 {
				return flag.ErrHelp
			}
			return download(ctx, args[0])
		},
	}
}

func download(_ context.Context, imageRef string) error {
	return nil
}
