package main

import (
	"context"
	"flag"

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

func upload(_ context.Context, signature, imageRef string) error {
	return nil
}
