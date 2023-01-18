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
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/spf13/cobra"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/internal/ui"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
)

func Clean() *cobra.Command {
	c := &options.CleanOptions{}

	cmd := &cobra.Command{
		Use:              "clean",
		Short:            "Remove all signatures from an image.",
		Example:          "  cosign clean <IMAGE>",
		Args:             cobra.ExactArgs(1),
		PersistentPreRun: options.BindViper,
		RunE: func(cmd *cobra.Command, args []string) error {
			return CleanCmd(cmd.Context(), c.Registry, c.CleanType, args[0], c.Force)
		},
	}

	c.AddFlags(cmd)
	return cmd
}

func CleanCmd(ctx context.Context, regOpts options.RegistryOptions, cleanType options.CleanType, imageRef string, force bool) error {
	if !force {
		ui.Warnf(ctx, prompt(cleanType))
		if err := ui.ConfirmContinue(ctx); err != nil {
			return err
		}
	}
	ref, err := name.ParseReference(imageRef, regOpts.NameOptions()...)
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
	case options.CleanTypeSignature:
		cleanTags = []name.Tag{sigRef}
	case options.CleanTypeSbom:
		cleanTags = []name.Tag{sbomRef}
	case options.CleanTypeAttestation:
		cleanTags = []name.Tag{attRef}
	case options.CleanTypeAll:
		cleanTags = []name.Tag{sigRef, attRef, sbomRef}
	default:
		panic("invalid CleanType value")
	}

	for _, t := range cleanTags {
		if err := remote.Delete(t, remoteOpts...); err != nil {
			var te *transport.Error
			if errors.As(err, &te) && te.StatusCode == http.StatusNotFound {
				// If the tag doesn't exist, some registries may
				// respond with a 404, which shouldn't be considered an
				// error.
			} else {
				fmt.Fprintf(os.Stderr, "could not delete %s from %s\n: %v\n", t, imageRef, err)
			}
		} else {
			fmt.Fprintf(os.Stderr, "Removed %s from %s\n", t, imageRef)
		}
	}

	return nil
}

func prompt(cleanType options.CleanType) string {
	switch cleanType {
	case options.CleanTypeSignature:
		return "this will remove all signatures from the image"
	case options.CleanTypeSbom:
		return "this will remove all SBOMs from the image"
	case options.CleanTypeAttestation:
		return "this will remove all attestations from the image"
	case options.CleanTypeAll:
		return "this will remove all signatures, SBOMs and attestations from the image"
	}
	panic("invalid CleanType value")
}
