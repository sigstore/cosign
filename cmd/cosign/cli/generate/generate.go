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

package generate

import (
	"context"
	"io"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/sigstore/pkg/signature/payload"
)

// nolint
func GenerateCmd(ctx context.Context, regOpts options.RegistryOptions, imageRef string, annotations map[string]interface{}, w io.Writer) error {
	ref, err := name.ParseReference(imageRef, regOpts.NameOptions()...)
	if err != nil {
		return err
	}
	ociremoteOpts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		return err
	}
	digest, err := ociremote.ResolveDigest(ref, ociremoteOpts...)
	if err != nil {
		return err
	}
	// Overwrite "ref" with a digest to avoid a race where we use a tag
	// multiple times, and it potentially points to different things at
	// each access.
	ref = digest

	json, err := (&payload.Cosign{Image: digest, Annotations: annotations}).MarshalJSON()
	if err != nil {
		return err
	}
	w.Write(json)
	return nil
}
