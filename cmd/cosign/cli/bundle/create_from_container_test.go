//
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

package bundle

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"

	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
)

type legacyFixture struct {
	digest  name.Digest
	keyPath string
	key     *ecdsa.PrivateKey
}

func newLegacyFixture(t *testing.T) *legacyFixture {
	t.Helper()
	s := httptest.NewServer(registry.New(registry.WithReferrersSupport(true)))
	t.Cleanup(s.Close)

	u, err := url.Parse(s.URL)
	checkErr(t, err)
	ref, err := name.ParseReference(fmt.Sprintf("%s/repo:tag", u.Host))
	checkErr(t, err)

	img, err := random.Image(10, 1)
	checkErr(t, err)
	checkErr(t, remote.Write(ref, img))
	h, err := img.Digest()
	checkErr(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	checkErr(t, err)
	pubPEM, err := cryptoutils.MarshalPublicKeyToPEM(key.Public())
	checkErr(t, err)
	keyPath := filepath.Join(t.TempDir(), "cosign.pub")
	checkErr(t, os.WriteFile(keyPath, pubPEM, 0600))

	return &legacyFixture{digest: ref.Context().Digest(h.String()), keyPath: keyPath, key: key}
}

func (f *legacyFixture) sign(t *testing.T, data []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(data)
	sig, err := f.key.Sign(rand.Reader, digest[:], crypto.SHA256)
	checkErr(t, err)
	return sig
}

func (f *legacyFixture) attachSignature(t *testing.T, opts ...static.Option) {
	t.Helper()
	payload := []byte(fmt.Sprintf(`{"critical":{"identity":{"docker-reference":%q},"image":{"docker-manifest-digest":%q},"type":"cosign container image signature"},"optional":null}`,
		f.digest.Context().String(), f.digest.DigestStr()))
	sig, err := static.NewSignature(payload, base64.StdEncoding.EncodeToString(f.sign(t, payload)), opts...)
	checkErr(t, err)

	se, err := ociremote.SignedEntity(f.digest)
	checkErr(t, err)
	se, err = mutate.AttachSignatureToEntity(se, sig)
	checkErr(t, err)
	checkErr(t, ociremote.WriteSignatures(f.digest.Repository, se))
}

func (f *legacyFixture) attachAttestation(t *testing.T, predicateType string) {
	t.Helper()
	statement := []byte(fmt.Sprintf(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":%q,"digest":{"sha256":%q}}],"predicateType":%q,"predicate":{}}`,
		f.digest.Context().String(), f.digest.DigestStr()[len("sha256:"):], predicateType))
	payloadType := "application/vnd.in-toto+json"
	envelope := dsse.Envelope{
		PayloadType: payloadType,
		Payload:     base64.StdEncoding.EncodeToString(statement),
		Signatures:  []dsse.Signature{{Sig: base64.StdEncoding.EncodeToString(f.sign(t, dsse.PAE(payloadType, statement)))}},
	}
	envelopeBytes, err := json.Marshal(envelope)
	checkErr(t, err)
	att, err := static.NewAttestation(envelopeBytes)
	checkErr(t, err)

	se, err := ociremote.SignedEntity(f.digest)
	checkErr(t, err)
	se, err = mutate.AttachAttestationToEntity(se, att)
	checkErr(t, err)
	checkErr(t, ociremote.WriteAttestations(f.digest.Repository, se))
}

func (f *legacyFixture) createFromContainerCmd() *CreateFromContainerCmd {
	return &CreateFromContainerCmd{CommonBundleCreateOptions: options.CommonBundleCreateOptions{IgnoreTlog: true, KeyRef: f.keyPath}}
}

func TestCreateFromContainerCmd(t *testing.T) {
	ctx := context.Background()
	f := newLegacyFixture(t)
	predicateType := "https://sigstore.dev/cosign/sign/v1"
	f.attachSignature(t)
	f.attachAttestation(t, predicateType)

	checkErr(t, f.createFromContainerCmd().Exec(ctx, f.digest.String()))

	bundles, _, err := cosign.GetBundles(ctx, f.digest, nil)
	checkErr(t, err)
	if len(bundles) != 1 {
		t.Fatalf("expected 1 bundle, got %d", len(bundles))
	}
	var sawDSSE bool
	for _, b := range bundles {
		if _, ok := b.Content.(*protobundle.Bundle_DsseEnvelope); ok {
			sawDSSE = true
		}
		if b.VerificationMaterial.GetPublicKey() == nil {
			t.Error("expected public key verification material")
		}
	}
	if !sawDSSE {
		t.Errorf("expected one DSSE bundle, got dsse=%v", sawDSSE)
	}

	index, err := ociremote.Referrers(f.digest, "")
	checkErr(t, err)
	for _, m := range index.Manifests {
		if m.Annotations["dev.sigstore.bundle.content"] == "dsse-envelope" && m.Annotations[ociremote.BundlePredicateType] != predicateType {
			t.Errorf("expected predicateType %q, got %q", predicateType, m.Annotations[ociremote.BundlePredicateType])
		}
	}

	// Running again must not push duplicates.
	checkErr(t, f.createFromContainerCmd().Exec(ctx, f.digest.String()))
	bundles, _, err = cosign.GetBundles(ctx, f.digest, nil)
	checkErr(t, err)
	if len(bundles) != 1 {
		t.Fatalf("expected 1 bundle after re-run, got %d", len(bundles))
	}
}

func TestCreateFromContainerCmd_NoLegacyMaterial(t *testing.T) {
	f := newLegacyFixture(t)

	if err := f.createFromContainerCmd().Exec(context.Background(), f.digest.String()); err == nil {
		t.Fatal("expected error when no legacy attestation exist")
	}
}
