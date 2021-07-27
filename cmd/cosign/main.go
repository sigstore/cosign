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
	"os"

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
	rootFlagSet    = flag.NewFlagSet("cosign", flag.ExitOnError)
	debug          = rootFlagSet.Bool("d", false, "log debug output")
	outputFilename = rootFlagSet.String("output-file", "", "log output to a file")
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
			cli.VerifyManifest(),
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

func printErrAndExit(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
