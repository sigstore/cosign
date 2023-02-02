package cosign

import (
	"context"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/layout"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
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

func InspectTlogEntries(
	ctx context.Context,
	client *client.Rekor,
	sig oci.Signature,
	pem []byte,
) (*[]models.LogEntryAnon, error) {
	b64sig, err := sig.Base64Signature()
	if err != nil {
		return nil, err
	}
	payload, err := sig.Payload()
	if err != nil {
		return nil, err
	}
	tlogEntries, err := FindTlogEntry(ctx, client, b64sig, payload, pem)
	if err != nil {
		return nil, err
	}
	if len(tlogEntries) == 0 {
		return nil, fmt.Errorf("no valid tlog entries found with proposed entry")
	}

	return &tlogEntries, nil
}

// InspectLocalImageSignatures retrieves signatures from a saved, local image, without any network calls, returning the verified signatures.
// If there were no signatures, we return an error.
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

// InspectLocalImageAttestations retrieves attestations from a saved, local image, without any network calls,
// returning the attestations.
// If there were no attestations, we return an error.
func InspectLocalImageAttestations(
	ctx context.Context,
	path string,
	co *CheckOpts,
) (checkedAttestations []oci.Signature, err error) {
	se, err := layout.SignedImageIndex(path)
	if err != nil {
		return nil, err
	}

	atts, err := se.Attestations()
	if err != nil {
		return nil, err
	}

	sl, err := atts.Get()
	if err != nil {
		return nil, err
	}

	return sl, nil
}

// InspectImageAttestations does all the main cosign checks in a loop, returning the verified attestations.
// If there were no valid attestations, we return an error.
func InspectImageAttestations(
	ctx context.Context,
	signedImgRef name.Reference,
	co *CheckOpts,
) (attestations []oci.Signature, err error) {
	// This is a carefully optimized sequence for fetching the attestations of
	// the entity that minimizes registry requests when supplied with a digest
	// input.
	digest, err := ociremote.ResolveDigest(signedImgRef, co.RegistryClientOpts...)
	if err != nil {
		return nil, err
	}
	st, err := ociremote.AttestationTag(digest, co.RegistryClientOpts...)
	if err != nil {
		return nil, err
	}
	atts, err := ociremote.Signatures(st, co.RegistryClientOpts...)
	if err != nil {
		return nil, err
	}

	sl, err := atts.Get()
	if err != nil {
		return nil, err
	}

	return sl, nil
}
