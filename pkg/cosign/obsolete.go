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

package cosign

import (
	"context"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v2/internal/ui"
	"github.com/sigstore/sigstore/pkg/signature/payload"
)

// ObsoletePayload returns the implied payload that some commands expect to match
// the signature if no payload is provided by the user.
// DO NOT ADD ANY NEW CALLERS OF THIS.
func ObsoletePayload(ctx context.Context, digestedImage name.Digest) ([]byte, error) {
	blob, err := (&payload.Cosign{Image: digestedImage}).MarshalJSON()
	if err != nil {
		return nil, err
	}
	ui.Warnf(ctx, "using obsolete implied signature payload data (with digested reference %s); specify it explicitly with --payload instead",
		digestedImage.Name())
	return blob, nil
}
