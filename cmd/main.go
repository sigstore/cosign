package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/peterbourgon/ff/v3/ffcli"
)

var (
	rootFlagSet = flag.NewFlagSet("cosign", flag.ExitOnError)
	verbose     = rootFlagSet.Bool("v", false, "increase log verbosity")
)

func main() {
	root := &ffcli.Command{
		ShortUsage:  "cosign [flags] <subcommand>",
		FlagSet:     rootFlagSet,
		Subcommands: []*ffcli.Command{Verify(), Sign(), Upload(), Generate(), Download(), GenerateKeyPair()},
		Exec: func(context.Context, []string) error {
			return flag.ErrHelp
		},
	}

	if err := root.ParseAndRun(context.Background(), os.Args[1:]); err != nil {
		if *verbose {
			fmt.Print("verbose!")
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
