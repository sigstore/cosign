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
	"github.com/sigstore/cosign/pkg/cosign"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
)

func Clean() *cobra.Command {
	c := &options.CleanOptions{}

	cmd := &cobra.Command{
		Use:     "clean",
		Short:   "Remove all signatures from an image.",
		Example: "  cosign clean <IMAGE>",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return CleanCmd(cmd.Context(), c.Registry, c.CleanType, args[0], c.Force)
		},
	}

	c.AddFlags(cmd)
	return cmd
}

func CleanCmd(ctx context.Context, regOpts options.RegistryOptions, cleanType, imageRef string, force bool) error {
	if !force {
		ok, err := cosign.ConfirmPrompt(prompt(cleanType))
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
	}

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return err
	}

	remoteOpts := regOpts.GetRegistryClientOpts(ctx)

	sigRef, err := ociremote.SignatureTag(ref, ociremote.WithRemoteOptions(remoteOpts...))
	if err != nil {
		return err
	}

	attRef, err := ociremote.AttestationTag(ref, ociremote.WithRemoteOptions(remoteOpts...))
	if err != nil {
		return err
	}

	sbomRef, err := ociremote.SBOMTag(ref, ociremote.WithRemoteOptions(remoteOpts...))
	if err != nil {
		return err
	}

	var cleanTags []name.Tag
	switch cleanType {
	case "signature":
		cleanTags = []name.Tag{sigRef}
	case "sbom":
		cleanTags = []name.Tag{sbomRef}
	case "attestation":
		cleanTags = []name.Tag{attRef}
	case "all":
		cleanTags = []name.Tag{sigRef, attRef, sbomRef}
	}

	for _, t := range cleanTags {
		fmt.Fprintf(os.Stderr, "Removing %s from %s\n", t.String(), imageRef)

		err = remote.Delete(t, remoteOpts...)
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not delete %s from %s\n: %v\n", t.String(), imageRef, err)
		}
	}

	return nil
}

func prompt(cleanType string) string {
	switch cleanType {
	case "signature":
		return "WARNING: this will remove all signatures from the image"
	case "sbom":
		return "WARNING: this will remove all SBOMs from the image"
	case "attestation":
		return "WARNING: this will remove all attestations from the image"
	case "all":
		return "WARNING: this will remove all signatures, SBOMs and attestations from the image"
	}
	return ""
}
