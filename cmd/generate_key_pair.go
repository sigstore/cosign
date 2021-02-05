package main

import (
	"context"
	"flag"

	"github.com/peterbourgon/ff/v3/ffcli"
)

func GenerateKeyPair() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign generate-key-pair", flag.ExitOnError)
	)

	return &ffcli.Command{
		Name:       "generate-key-pair",
		ShortUsage: "cosign generate-key-pair",
		ShortHelp:  "generate-key-pair generates a key-pair",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			return generateKeyPair(ctx)
		},
	}
}

func generateKeyPair(ctx context.Context) error {
	return nil
}
