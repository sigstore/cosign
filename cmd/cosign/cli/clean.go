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
	"fmt"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/spf13/cobra"

	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
)

func Clean() *cobra.Command {
	o := &options.RegistryOptions{}

	cmd := &cobra.Command{
		Use:     "clean",
		Short:   "Remove all signatures from an image.",
		Example: "  cosign clean <IMAGE>",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return CleanCmd(cmd.Context(), *o, args[0])
		},
	}

	o.AddFlags(cmd)
	return cmd
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
