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
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/internal/ui"
	"github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/spf13/cobra"
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
		ui.Warnf(ctx, prompt(cleanType)) //nolint:govet // practically const
		if err := ui.ConfirmContinue(ctx); err != nil {
			return err
		}
	}
	ref, err := name.ParseReference(imageRef, regOpts.NameOptions()...)
	if err != nil {
		return err
	}

	remoteOpts := regOpts.GetRegistryClientOpts(ctx)
	ociRemoteOpts := ociremote.WithRemoteOptions(remoteOpts...)

	sigRef, err := ociremote.SignatureTag(ref, ociRemoteOpts)
	if err != nil {
		return err
	}

	attRef, err := ociremote.AttestationTag(ref, ociRemoteOpts)
	if err != nil {
		return err
	}

	sbomRef, err := ociremote.SBOMTag(ref, ociRemoteOpts)
	if err != nil {
		return err
	}

	referrerRefs := []name.Reference{}
	digest, ok := ref.(name.Digest)
	if !ok {
		var err error
		digest, err = ociremote.ResolveDigest(ref, ociRemoteOpts)
		if err != nil {
			return fmt.Errorf("resolving digest: %w", err)
		}
	}
	idx, err := remote.Referrers(digest, remoteOpts...)
	if err != nil {
		return err
	}
	if idx != nil {
		// Delete manifest
		imgDigest, err := idx.Digest()
		if err != nil {
			return err
		}
		referrerDigestStr := fmt.Sprintf("%s@%s", ref.Context().Name(), imgDigest.String())
		referrerDigest, err := name.NewDigest(referrerDigestStr)
		if err != nil {
			return err
		}
		referrerRefs = append(referrerRefs, referrerDigest)

		// Delete layers in the manifest
		idxManifest, err := idx.IndexManifest()
		if err != nil {
			return err
		}
		if idxManifest != nil {
			for _, manifest := range idxManifest.Manifests {
				layerDigestStr := fmt.Sprintf("%s@%s", ref.Context().Name(), manifest.Digest.String())
				layerDigest, err := name.NewDigest(layerDigestStr)
				if err != nil {
					return err
				}
				layerImage, err := remote.Image(layerDigest, remoteOpts...)
				if err != nil {
					return err
				}
				layerManifest, err := layerImage.Manifest()
				if err != nil {
					return err
				}
				if layerManifest != nil {
					if layerManifest.Config.ArtifactType == bundle.BundleV03MediaType {
						referrerRefs = append(referrerRefs, layerDigest)
					}
				}
			}
		}
	}

	var cleanTags []name.Reference
	switch cleanType {
	case options.CleanTypeSignature:
		cleanTags = []name.Reference{sigRef}
		if len(referrerRefs) > 0 {
			ui.Warnf(ctx, "image has referrers, consider using --referrer")
		}
	case options.CleanTypeSbom:
		cleanTags = []name.Reference{sbomRef}
	case options.CleanTypeAttestation:
		cleanTags = []name.Reference{attRef}
		if len(referrerRefs) > 0 {
			ui.Warnf(ctx, "image has referrers, consider using --referrer")
		}
	case options.CleanTypeReferrer:
		cleanTags = referrerRefs
	case options.CleanTypeAll:
		cleanTags = append([]name.Reference{sigRef, attRef, sbomRef}, referrerRefs...)
	default:
		return errors.New("invalid CleanType value")
	}

	for _, t := range cleanTags {
		if err := remote.Delete(t, remoteOpts...); err != nil {
			var te *transport.Error
			switch {
			case errors.As(err, &te) && te.StatusCode == http.StatusNotFound:
				// If the tag doesn't exist, some registries may
				// respond with a 404, which shouldn't be considered an
				// error.
			case errors.As(err, &te) && te.StatusCode == http.StatusBadRequest:
				// Docker registry >=v2.3 requires does not allow deleting the OCI object name directly, must use the digest instead.
				// See https://github.com/distribution/distribution/blob/main/docs/content/spec/api.md#deleting-an-image
				tTag, ok := t.(name.Tag)
				if ok {
					if err := deleteByDigest(tTag, remoteOpts...); err != nil {
						if errors.As(err, &te) && te.StatusCode == http.StatusNotFound { //nolint: revive
						} else {
							fmt.Fprintf(os.Stderr, "could not delete %s by digest from %s:\n%v\n", t, imageRef, err)
						}
					} else {
						fmt.Fprintf(os.Stderr, "Removed %s from %s\n", t, imageRef)
					}
				}
			default:
				fmt.Fprintf(os.Stderr, "could not delete %s from %s:\n%v\n", t, imageRef, err)
			}
		} else {
			fmt.Fprintf(os.Stderr, "Removed %s from %s\n", t, imageRef)
		}
	}

	return nil
}

func deleteByDigest(tag name.Tag, opts ...remote.Option) error {
	digestTag, err := ociremote.DockerContentDigest(tag, ociremote.WithRemoteOptions(opts...))
	if err != nil {
		return err
	}
	return remote.Delete(digestTag, opts...)
}

func prompt(cleanType options.CleanType) string {
	switch cleanType {
	case options.CleanTypeSignature:
		return "this will remove all signatures from the image"
	case options.CleanTypeSbom:
		return "this will remove all SBOMs from the image"
	case options.CleanTypeAttestation:
		return "this will remove all attestations from the image"
	case options.CleanTypeReferrer:
		return "this will remove all referrer attestations and/or signatures from the image"
	case options.CleanTypeAll:
		return "this will remove all signatures, SBOMs and attestations from the image"
	}
	panic("invalid CleanType value")
}
