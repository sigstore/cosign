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
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/internal/ui"
	"github.com/sigstore/cosign/v2/pkg/cosign"
)

func AttestationCmd(ctx context.Context, regOpts options.RegistryOptions, attOptions options.AttestationDownloadOptions, imageRef string) error {
	ref, err := name.ParseReference(imageRef, regOpts.NameOptions()...)
	if err != nil {
		return err
	}
	if _, ok := ref.(name.Digest); !ok {
		msg := fmt.Sprintf(ui.TagReferenceMessage, imageRef)
		ui.Warnf(ctx, msg)
	}
	ociremoteOpts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		return err
	}

	var predicateURI string
	if attOptions.PredicateType != "" {
		predicateURI, err = options.ParsePredicateType(attOptions.PredicateType)
		if err != nil {
			return err
		}
	}

	attestations, err := cosign.FetchAttestationsForReference(ctx, ref, predicateURI, ociremoteOpts...)
	if err != nil {
		return err
	}

	for _, att := range attestations {
		b, err := json.Marshal(att)
		if err != nil {
			return err
		}
		fmt.Println(string(b))
	}
	return nil
}
