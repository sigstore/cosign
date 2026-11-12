// Copyright 2026 The Sigstore Authors.
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

package signcommon

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAttestationBundleSkipIfSigned(t *testing.T) {
	ctx := context.Background()
	digest := pushRandomImage(t)
	keyA := writeKeyPair(t)
	keyB := writeKeyPair(t)
	const sbom, provenance = "https://spdx.dev/Document", "https://slsa.dev/provenance/v1"

	attest := func(keyRef, predicateType string) error {
		ko := options.KeyOpts{KeyRef: keyRef, PassFunc: pass("pw"), SkipConfirmation: true}
		sc, err := NewSigningConfigFromKeyOpts(ko)
		require.NoError(t, err)
		opts := CommonBundleOpts{
			Payload:       []byte(fmt.Sprintf(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"digest":{"sha256":%q}}],"predicateType":%q,"predicate":{}}`, digest.DigestStr()[len("sha256:"):], predicateType)),
			Digest:        digest,
			PredicateType: predicateType,
			Upload:        true,
			SkipIfSigned:  true,
		}
		bundle, _, _, err := NewAttestationBundle(ctx, ko, "", "", opts, sc, nil)
		if err != nil {
			return err
		}
		return ociremote.WriteAttestationNewBundleFormat(digest, bundle, predicateType)
	}
	bundles := func() int {
		b, _, err := cosign.GetBundles(ctx, digest, nil)
		require.NoError(t, err)
		return len(b)
	}

	require.NoError(t, attest(keyA, sbom))
	assert.ErrorIs(t, attest(keyA, sbom), ErrAlreadySigned)
	assert.Equal(t, 1, bundles())

	require.NoError(t, attest(keyB, sbom), "another key is another identity")
	require.NoError(t, attest(keyA, provenance), "another predicate type is not a duplicate")
	assert.Equal(t, 3, bundles())
}

func pushRandomImage(t *testing.T) name.Digest {
	t.Helper()
	s := httptest.NewServer(registry.New(registry.WithReferrersSupport(true)))
	t.Cleanup(s.Close)
	u, err := url.Parse(s.URL)
	require.NoError(t, err)
	ref, err := name.ParseReference(u.Host + "/repo:tag")
	require.NoError(t, err)
	img, err := random.Image(10, 1)
	require.NoError(t, err)
	require.NoError(t, remote.Write(ref, img))
	h, err := img.Digest()
	require.NoError(t, err)
	return ref.Context().Digest(h.String())
}

func writeKeyPair(t *testing.T) string {
	t.Helper()
	keys, err := cosign.GenerateKeyPair(pass("pw"))
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "cosign.key")
	require.NoError(t, os.WriteFile(path, keys.PrivateBytes, 0600))
	return path
}
