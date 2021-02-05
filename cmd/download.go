package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"

	"github.com/dlorenc/cosign/pkg"
	"github.com/google/go-containerregistry/pkg/name"
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
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return err
	}

	signatures, err := pkg.FetchSignatures(ref)
	if err != nil {
		return err
	}
	for _, sig := range signatures {
		b, err := json.Marshal(sig)
		if err != nil {
			return err
		}
		fmt.Println(string(b))
	}
	return nil
}
