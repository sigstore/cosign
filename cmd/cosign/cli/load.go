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

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/pkg/oci/layout"
	"github.com/sigstore/cosign/v2/pkg/oci/remote"

	"github.com/spf13/cobra"
)

func Load() *cobra.Command {
	o := &options.LoadOptions{}

	cmd := &cobra.Command{
		Use:     "load",
		Short:   "Load a signed image on disk to a remote registry",
		Long:    "Load a signed image on disk to a remote registry",
		Example: `  cosign load --dir <path to directory> <IMAGE> OR cosign load --dir <path to directory> --registry <REGISTRY>`,
		//Args:             cobra.ExactArgs(1),
		PersistentPreRun: options.BindViper,
		RunE: func(cmd *cobra.Command, args []string) error {
			if o.Registry.Name != "" && len(args) != 0 {
				return fmt.Errorf("both --registry and image argument provided, only one should be used")
			}
			if o.Registry.Name != "" && len(args) == 0 {
				return LoadCmd(cmd.Context(), *o, "")
			}
			if len(args) != 1 {
				return fmt.Errorf("image argument is required")
			}
			return LoadCmd(cmd.Context(), *o, args[0])
		},
	}

	o.AddFlags(cmd)
	return cmd
}

func LoadCmd(ctx context.Context, opts options.LoadOptions, imageRef string) error {
	var ref name.Reference
	var err error
	if opts.Registry.Name == "" {
		// Use the provided image reference
		ref, err = name.ParseReference(imageRef)
		if err != nil {
			return fmt.Errorf("parsing image name %s: %w", imageRef, err)
		}
	}

	// get the signed image(s) from disk
	sii, err := layout.SignedImageIndex(opts.Directory)
	if err != nil {
		return fmt.Errorf("signed image index: %w", err)
	}

	ociremoteOpts, err := opts.Registry.ClientOpts(ctx)
	if err != nil {
		return err
	}

	if opts.Registry.Name == "" {
		return remote.WriteSignedImageIndexImages(ref, sii, ociremoteOpts...)
	}
	return remote.WriteSignedImageIndexImagesBulk(opts.Registry.Name, sii, ociremoteOpts...)
}
