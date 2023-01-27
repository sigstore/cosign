package cosign

import (
	"context"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/layout"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
)

// InspectImageSignatures returns the signatures against a signed image reference.
// If there were no signatures, we return an error.
// WARNING: This function does not perform any signature verification
func InspectImageSignatures(
	ctx context.Context,
	signedImgRef name.Reference,
	co *CheckOpts,
) (Signatures []oci.Signature, err error) {
	// This is a carefully optimized sequence for fetching the signatures of the
	// entity that minimizes registry requests when supplied with a digest input
	digest, err := ociremote.ResolveDigest(signedImgRef, co.RegistryClientOpts...)
	if err != nil {
		return nil, err
	}
	// h, err := v1.NewHash(digest.Identifier())
	// if err != nil {
	// 	return nil, err
	// }

	var sigs oci.Signatures
	sigRef := co.SignatureRef
	if sigRef == "" {
		st, err := ociremote.SignatureTag(digest, co.RegistryClientOpts...)
		if err != nil {
			return nil, err
		}
		sigs, err = ociremote.Signatures(st, co.RegistryClientOpts...)
		if err != nil {
			return nil, err
		}
	} else {
		sigs, err = loadSignatureFromFile(sigRef, signedImgRef, co)
		if err != nil {
			return nil, err
		}
	}

	sl, err := sigs.Get()
	if err != nil {
		return nil, err
	}

	return sl, nil
}

// InspectLocalImageSignatures verifies signatures from a saved, local image, without any network calls, returning the verified signatures.
// If there were no valid signatures, we return an error.
func InspectLocalImageSignatures(
	ctx context.Context,
	path string,
	co *CheckOpts,
) (signatures []oci.Signature, err error) {
	se, err := layout.SignedImageIndex(path)
	if err != nil {
		return nil, err
	}

	sigs, err := se.Signatures()
	if err != nil {
		return nil, err
	}

	sl, err := sigs.Get()
	if err != nil {
		return nil, err
	}

	return sl, nil
}
