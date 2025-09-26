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
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v3/internal/ui"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestObsoletePayload(t *testing.T) {
	// This looks like a smoke test, but the property of generating _exactly_ the same string as previous versions is
	// essential.
	digestedImg, err := name.NewDigest("docker.io/namespace/image@sha256:4aa3054270f7a70b4528f2064ee90961788e1e1518703592ae4463de3b889dec")
	require.NoError(t, err)
	var res []byte
	stderr := ui.RunWithTestCtx(func(ctx context.Context, _ ui.WriteFunc) {
		r, err := ObsoletePayload(ctx, digestedImg)
		require.NoError(t, err)
		res = r
	})
	assert.Contains(t, stderr, "obsolete implied signature payload")
	assert.Equal(t, []byte(`{"critical":{"identity":{"docker-reference":"index.docker.io/namespace/image"},"image":{"docker-manifest-digest":"sha256:4aa3054270f7a70b4528f2064ee90961788e1e1518703592ae4463de3b889dec"},"type":"cosign container image signature"},"optional":null}`), res)
}
