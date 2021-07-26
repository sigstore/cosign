//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/riywo/loginshell"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/pkg/errors"

	"github.com/sigstore/cosign/cmd/cosign/cli"
	"github.com/sigstore/cosign/cmd/cosign/cli/attach"
	"github.com/sigstore/cosign/cmd/cosign/cli/download"
	"github.com/sigstore/cosign/cmd/cosign/cli/pivcli"
	"github.com/sigstore/cosign/cmd/cosign/cli/upload"
)

var (
	rootFlagSet       = flag.NewFlagSet("cosign", flag.ExitOnError)
	debug             = rootFlagSet.Bool("d", false, "log debug output")
	outputFilename    = rootFlagSet.String("output-file", "", "log output to a file")
	completionEnabled = rootFlagSet.Bool("completion", false, "generate completion for current shell")
)

func main() {
	root := &ffcli.Command{
		ShortUsage: "cosign [flags] <subcommand>",
		FlagSet:    rootFlagSet,
		Subcommands: []*ffcli.Command{
			// Key Management
			cli.PublicKey(),
			cli.GenerateKeyPair(),
			// Signing
			cli.Verify(),
			cli.Sign(),
			cli.Attest(),
			cli.Generate(),
			cli.SignBlob(),
			cli.VerifyAttestation(),
			cli.VerifyBlob(),
			cli.VerifyDockerfile(),
			// Upload sub-tree
			upload.Upload(),
			// Download sub-tree
			download.Download(),
			// Attach sub-tree
			attach.Attach(),
			// PIV sub-tree
			pivcli.PivKey(),
			// PIV sub-tree
			cli.Copy(),
			cli.Clean(),
			cli.Triangulate(),
			// Version
			cli.Version()},
		Exec: func(context.Context, []string) error {
			return flag.ErrHelp
		},
	}

	if err := root.Parse(os.Args[1:]); err != nil {
		printErrAndExit(err)
	}

	if *completionEnabled {
		generateCompletionForCurrentShell(root)
		os.Exit(0)
	}

	if *outputFilename != "" {
		out, err := os.Create(*outputFilename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", errors.Wrapf(err, "Error creating output file %s", *outputFilename))
			os.Exit(1)
		}
		stdout := os.Stdout
		defer func() {
			os.Stdout = stdout
			out.Close()
		}()
		os.Stdout = out
	}

	if *debug {
		logs.Debug.SetOutput(os.Stderr)
	}

	if err := root.Run(context.Background()); err != nil {
		printErrAndExit(err)
	}
}

func generateCompletionForCurrentShell(root *ffcli.Command) {
	shell, err := loginshell.Shell()
	if err != nil {
		printErrAndExit(err)
	}

	if strings.EqualFold(shell, "/bin/zsh") {
		var rootCmpl []string
		rootCmdName := root.FlagSet.Name()
		fmt.Printf("#compdef _%s %s\n\n", rootCmdName, rootCmdName)
		root.FlagSet.VisitAll(func(f *flag.Flag) {
			rootCmpl = append(
				rootCmpl, fmt.Sprintf("\t'-%s[%s]' \\\n", f.Name, f.Usage))
		})
		fmt.Printf("function _%s {\n\n local -a commands \n _arguments -C \\\n%s",
			rootCmdName, strings.Join(rootCmpl, " "))
		printSubCommands(root, rootCmdName)
		printCommandFunctions(root, rootCmdName)
	} else {
		fmt.Fprintf(os.Stderr, "we are not currently supporting the shell %s for completions: %v\n", shell, err)
		os.Exit(1)
	}
}

func printCommandFunctions(root *ffcli.Command, parentCmdName string) {
	for _, cmd := range root.Subcommands {
		var sbCmpl []string
		if cmd.Name == "" {
			continue
		}
		cmd.FlagSet.VisitAll(func(f *flag.Flag) {
			sbCmpl = append(
				sbCmpl, fmt.Sprintf("\t'-%s[%s]' \\\n", f.Name, f.Usage))
		})
		fields := strings.Fields(parentCmdName)
		if len(fields) > 0 {
			parentCmdName = strings.Join(fields, "_")
		}
		fmt.Printf("function _%s_%s {\n\n local -a commands \n _arguments -C \\\n%s",
			parentCmdName, cmd.Name, strings.Join(sbCmpl, " "))
		printSubCommands(cmd, cmd.FlagSet.Name())
		printCommandFunctions(cmd, cmd.FlagSet.Name())
	}
}

func printSubCommands(cmd *ffcli.Command, parentCmdName string) {
	fmt.Print("\t\"*::arg:->args\"")
	if len(cmd.Subcommands) > 0 {
		fmt.Println("\t \\")
		fmt.Print("\t\"1: :->cmnds\"\n\n")
		fmt.Println(" case $state in")
		fmt.Println("\tcmnds)")
		fmt.Println("\t commands=(")
		for _, sbc := range cmd.Subcommands {
			if sbc.Name == "" {
				continue
			}
			fmt.Printf("\t \"%s:%s\"\n", sbc.Name, sbc.ShortHelp)
		}
		fmt.Println("\t)")
		fmt.Println("\t _describe \"command\" commands\n\t ;;\n esac")

		fmt.Println(" case \"$words[1]\" in")
		for _, sbc := range cmd.Subcommands {
			if sbc.Name == "" {
				continue
			}
			fmt.Printf("\t%s)\n", sbc.Name)
			fields := strings.Fields(parentCmdName)
			if len(fields) > 0 {
				parentCmdName = strings.Join(fields, "_")
			}
			fmt.Printf("\t _%s_%s\n", parentCmdName, sbc.Name)
			fmt.Println("\t ;;")
		}
		fmt.Print(" esac")
	}
	fmt.Print("\n}\n\n")
}

func printErrAndExit(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
