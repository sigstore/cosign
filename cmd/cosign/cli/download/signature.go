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

package download

import (
	"context"
	"encoding/json"
	"io"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/pkg/cosign"
)

func SignatureCmd(ctx context.Context, regOpts options.RegistryOptions, imageRef string, out io.Writer) error {
	ref, err := name.ParseReference(imageRef, regOpts.NameOptions()...)
	if err != nil {
		return err
	}
	ociremoteOpts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		return err
	}

	// Try bundles first
	newBundles, _, err := cosign.GetBundles(ctx, ref, ociremoteOpts)
	if err == nil && len(newBundles) > 0 {
		for _, eachBundle := range newBundles {
			b, err := json.Marshal(eachBundle)
			if err != nil {
				return err
			}
			_, err = out.Write(append(b, byte('\n')))
			if err != nil {
				return err
			}
		}
		return nil
	}

	signatures, err := cosign.FetchSignaturesForReference(ctx, ref, ociremoteOpts...)
	if err != nil {
		return err
	}
	for _, sig := range signatures {
		b, err := json.Marshal(sig)
		if err != nil {
			return err
		}
		_, err = out.Write(append(b, byte('\n')))
		if err != nil {
			return err
		}
	}
	return nil
}
