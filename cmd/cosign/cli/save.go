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

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/sigstore/cosign/v3/pkg/oci/layout"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/spf13/cobra"
)

func Save() *cobra.Command {
	o := &options.SaveOptions{}

	cmd := &cobra.Command{
		Use:              "save",
		Short:            "Save the container image and associated signatures to disk at the specified directory.",
		Long:             "Save the container image and associated signatures to disk at the specified directory.",
		Example:          `  cosign save --dir <path to directory> <IMAGE>`,
		Args:             cobra.ExactArgs(1),
		PersistentPreRun: options.BindViper,
		RunE: func(cmd *cobra.Command, args []string) error {
			return SaveCmd(cmd.Context(), *o, args[0])
		},
	}

	o.AddFlags(cmd)
	return cmd
}

func SaveCmd(ctx context.Context, opts options.SaveOptions, imageRef string) error {
	regOpts := opts.Registry
	regClientOpts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		return fmt.Errorf("constructing client options: %w", err)
	}

	ref, err := name.ParseReference(imageRef, opts.Registry.NameOptions()...)
	if err != nil {
		return fmt.Errorf("parsing image name %s: %w", imageRef, err)
	}

	// See if we are using referrers
	digest, ok := ref.(name.Digest)
	if !ok {
		var err error
		digest, err = ociremote.ResolveDigest(ref, regClientOpts...)
		if err != nil {
			return fmt.Errorf("resolving digest: %w", err)
		}
	}

	indexManifest, err := ociremote.Referrers(digest, "", regClientOpts...)
	if err != nil {
		return fmt.Errorf("getting referrers: %w", err)
	}

	for _, manifest := range indexManifest.Manifests {
		if manifest.ArtifactType == "" {
			continue
		}
		artifactRef := ref.Context().Digest(manifest.Digest.String())
		si, err := ociremote.SignedImage(artifactRef, regClientOpts...)
		if err != nil {
			return fmt.Errorf("getting signed image: %w", err)
		}
		err = layout.WriteSignedImage(opts.Directory, si)
		if err != nil {
			return err
		}
	}

	se, err := ociremote.SignedEntity(ref, regClientOpts...)
	if err != nil {
		return fmt.Errorf("signed entity: %w", err)
	}

	if _, ok := se.(oci.SignedImage); ok {
		si, err := ociremote.SignedImage(ref, regClientOpts...)
		if err != nil {
			return fmt.Errorf("getting signed image: %w", err)
		}
		return layout.WriteSignedImage(opts.Directory, si)
	}

	if _, ok := se.(oci.SignedImageIndex); ok {
		sii, err := ociremote.SignedImageIndex(ref, regClientOpts...)
		if err != nil {
			return fmt.Errorf("getting signed image index: %w", err)
		}
		return layout.WriteSignedImageIndex(opts.Directory, sii)
	}
	return errors.New("unknown signed entity")
}
