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
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/spf13/cobra"
)

func Tree() *cobra.Command {
	c := &options.TreeOptions{}

	cmd := &cobra.Command{
		Use:              "tree",
		Short:            "Display supply chain security related artifacts for an image such as signatures, SBOMs and attestations",
		Example:          "  cosign tree <IMAGE>",
		Args:             cobra.ExactArgs(1),
		PersistentPreRun: options.BindViper,
		RunE: func(cmd *cobra.Command, args []string) error {
			return TreeCmd(cmd.Context(), c.Registry, c.RegistryExperimental, c.ExperimentalOCI11, args[0])
		},
	}

	c.AddFlags(cmd)
	return cmd
}

type OCIRelationsKey struct {
	artifactType   string
	artifactDigest name.Digest
}

func TreeCmd(ctx context.Context, regOpts options.RegistryOptions, regExpOpts options.RegistryExperimentalOptions, experimentalOCI11 bool, imageRef string) error {
	scsaMap := map[name.Tag][]v1.Layer{}
	ociRelationsMap := map[OCIRelationsKey][]v1.Layer{}

	ref, err := name.ParseReference(imageRef, regOpts.NameOptions()...)
	if err != nil {
		return err
	}

	remoteOpts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "📦 Supply Chain Security Related artifacts for an image: %s\n", ref.String())

	simg, err := ociremote.SignedEntity(ref, remoteOpts...)
	if err != nil {
		return err
	}

	// Handle the legacy mode first, always
	attRef, err := ociremote.AttestationTag(ref, remoteOpts...)
	if err != nil {
		return err
	}

	atts, err := simg.Attestations()
	if err == nil {
		layers, err := atts.Layers()
		if err != nil {
			return err
		}
		if len(layers) > 0 {
			scsaMap[attRef] = layers
		}
	}

	sigRef, err := ociremote.SignatureTag(ref, remoteOpts...)
	if err != nil {
		return err
	}

	sigs, err := simg.Signatures()
	if err == nil {
		layers, err := sigs.Layers()
		if err != nil {
			return err
		}
		if len(layers) > 0 {
			scsaMap[sigRef] = layers
		}
	}

	sbomRef, err := ociremote.SBOMTag(ref, remoteOpts...)
	if err != nil {
		return err
	}

	sbombs, err := simg.Attachment(ociremote.SBOMTagSuffix)
	if err == nil {
		layers, err := sbombs.Layers()
		if err != nil {
			return err
		}
		if len(layers) > 0 {
			scsaMap[sbomRef] = layers
		}
	}

	// Handle the experimental OCI 1.1 mode
	if regExpOpts.RegistryReferrersMode == options.RegistryReferrersModeOCI11 || experimentalOCI11 {
		// Handle OCI 1.1 mode
		digest, ok := ref.(name.Digest)
		if !ok {
			var err error
			digest, err = ociremote.ResolveDigest(ref, remoteOpts...)
			if err != nil {
				return fmt.Errorf("resolving digest: %w", err)
			}
		}

		// Get all referrers
		indexManifest, err := ociremote.Referrers(digest, "", remoteOpts...)
		if err != nil {
			return fmt.Errorf("getting referrers: %w", err)
		}

		// Group referrers by artifact type
		for _, manifest := range indexManifest.Manifests {
			if manifest.ArtifactType == "" {
				continue
			}

			// Fetch the image for this artifact
			artifactRef := ref.Context().Digest(manifest.Digest.String())
			artifactImage, err := ociremote.SignedImage(artifactRef, remoteOpts...)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error fetching artifact %s: %v\n", artifactRef, err)
				continue
			}

			// Get layers for this artifact
			layers, err := artifactImage.Layers()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error fetching layers for artifact %s: %v\n", artifactRef, err)
				continue
			}

			// Add to the map
			key := OCIRelationsKey{manifest.ArtifactType, artifactRef}
			ociRelationsMap[key] = append(ociRelationsMap[key], layers...)
		}
	}

	if len(scsaMap) == 0 && len(ociRelationsMap) == 0 {
		fmt.Fprintf(os.Stdout, "No Supply Chain Security Related Artifacts found for image %s,\n start creating one with simply running"+
			"$ cosign sign <img>", ref.String())
		return nil
	}

	for t, k := range scsaMap {
		switch t {
		case sigRef:
			fmt.Fprintf(os.Stdout, "└── 🔐 Signatures for an image tag: %s\n", t.String())
		case sbomRef:
			fmt.Fprintf(os.Stdout, "└── 📦 SBOMs for an image tag: %s\n", t.String())
		case attRef:
			fmt.Fprintf(os.Stdout, "└── 💾 Attestations for an image tag: %s\n", t.String())
		}

		if err := printLayers(k); err != nil {
			return err
		}
	}

	for key, layers := range ociRelationsMap {
		emoji := "🔗"

		// TODO - We could apply different emojis here for different values of key.artifactType

		fmt.Fprintf(os.Stdout, "└── %s %s artifacts via OCI referrer: %s\n", emoji, key.artifactType, key.artifactDigest)
		if err := printLayers(layers); err != nil {
			return err
		}
	}

	return nil
}

func printLayers(layers []v1.Layer) error {
	for i, l := range layers {
		last := i == len(layers)-1
		var sym string
		if last {
			sym = "   └──"
		} else {
			sym = "   ├──"
		}
		digest, err := l.Digest()
		if err != nil {
			return err
		}
		fmt.Printf("%s 🍒 %s\n", sym, digest)
	}
	return nil
}
