package cli

import (
	"context"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// Digest returns the digest of the image at the reference.
//
// If the reference is by digest already, it simply extracts the digest.
// Otherwise, it looks up the digest from the registry.
func Digest(ctx context.Context, ref name.Reference) (v1.Hash, error) {

	// If the image ref contains the digest, use it.
	// Otherwise, look up the digest the tag currently points to.
	if d, ok := ref.(name.Digest); ok {
		return v1.NewHash(d.DigestStr())
	} else {
		desc, err := remote.Get(ref, DefaultRegistryClientOpts(ctx)...)
		if err != nil {
			return v1.Hash{}, err
		}
		return desc.Digest, nil
	}
}
