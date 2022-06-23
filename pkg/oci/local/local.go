package local

import (
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/daemon"
	"github.com/sigstore/cosign/pkg/oci"
)

// These enable mocking for unit testing without faking an entire registry.
var (
	localWrite = daemon.Write
)

func WriteLocalImage(ref name.Reference, sii oci.SignedImageIndex) error {

	// write the image if there is one
	si, err := sii.SignedImage(v1.Hash{})
	if err != nil {
		return fmt.Errorf("signed image: %w", err)
	}
	_, err = localWrite(ref.(name.Tag), si)
	if err != nil {
		return fmt.Errorf("remote write: %w", err)
	}

	return nil
}
