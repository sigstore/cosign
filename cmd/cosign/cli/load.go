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
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/pkg/oci/layout"
	"github.com/sigstore/cosign/pkg/oci/remote"
	"github.com/spf13/cobra"
)

func Load() *cobra.Command {
	o := &options.LoadOptions{}

	cmd := &cobra.Command{
		Use:     "load",
		Short:   "Load a signed image on disk to a remote registry",
		Long:    "Load a signed image on disk to a remote registry",
		Example: `  cosign load --dir <path to directory> <IMAGE>`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return LoadCmd(cmd.Context(), *o, args[0])
		},
	}

	o.AddFlags(cmd)
	return cmd
}

func LoadCmd(ctx context.Context, opts options.LoadOptions, imageRef string) error {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return fmt.Errorf("parsing image name %s: %w", imageRef, err)
	}

	// get the signed image from disk
	sii, err := layout.SignedImageIndex(opts.Directory)
	if err != nil {
		return fmt.Errorf("signed image index: %w", err)
	}
	return remote.WriteSignedImageIndexImages(ref, sii)
}
