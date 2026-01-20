package cosign

import (
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func TestDeterministicLastDescriptorByDigestIsOrderIndependent(t *testing.T) {
	a := v1.Descriptor{Digest: v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("a", 64)}}
	b := v1.Descriptor{Digest: v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("b", 64)}}
	c := v1.Descriptor{Digest: v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("c", 64)}}

	orig := []v1.Descriptor{b, a, c}
	got := deterministicLastDescriptorByDigest(orig)
	if got.Digest.String() != c.Digest.String() {
		t.Fatalf("got %q, want %q", got.Digest.String(), c.Digest.String())
	}
	if orig[0].Digest.String() != b.Digest.String() || orig[1].Digest.String() != a.Digest.String() || orig[2].Digest.String() != c.Digest.String() {
		t.Fatalf("unexpected input mutation: got %v", []string{orig[0].Digest.String(), orig[1].Digest.String(), orig[2].Digest.String()})
	}

	got = deterministicLastDescriptorByDigest([]v1.Descriptor{c, b, a})
	if got.Digest.String() != c.Digest.String() {
		t.Fatalf("got %q, want %q", got.Digest.String(), c.Digest.String())
	}
}
