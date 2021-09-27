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

package cli

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/spf13/cobra"

	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
)

func addClean(topLevel *cobra.Command) {
	o := &options.RegistryOptions{}

	cmd := &cobra.Command{
		Use:   "clean",
		Short: "Remove all signatures from an image.\ncosign clean <image uri>",
		Long:  "Remove all signatures from an image.",

		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return flag.ErrHelp
			}

			return CleanCmd(cmd.Context(), *o, args[0])
		},
	}

	o.AddFlags(cmd)
	topLevel.AddCommand(cmd)
}

// Clean subcommand for ffcli.
// Deprecated: this will be deleted when the migration from ffcli to cobra is done.
func Clean() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("cosign clean", flag.ExitOnError)
		regOpts options.RegistryOptions
	)
	options.ApplyRegistryFlags(&regOpts, flagset)
	return &ffcli.Command{
		Name:       "clean",
		ShortUsage: "cosign clean <image uri>",
		ShortHelp:  "Remove all signatures from an image",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			panic("this command is now implemented in cobra.")
		},
	}
}

func CleanCmd(ctx context.Context, regOpts options.RegistryOptions, imageRef string) error {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return err
	}

	remoteOpts := regOpts.GetRegistryClientOpts(ctx)
	sigRef, err := ociremote.SignatureTag(ref, ociremote.WithRemoteOptions(remoteOpts...))
	if err != nil {
		return err
	}
	fmt.Println(sigRef)

	fmt.Fprintln(os.Stderr, "Deleting signature metadata...")

	err = remote.Delete(sigRef, remoteOpts...)
	if err != nil {
		return err
	}

	return nil
}
