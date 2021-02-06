package pkg

import (
	"encoding/json"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func Payload(img v1.Descriptor) ([]byte, error) {

	simpleSigning := SimpleSigning{
		Critical: Critical{
			Image: Image{
				DockerManifestDigest: img.Digest.Hex,
			},
			Type: "cosign container signature",
		},
	}

	b, err := json.Marshal(simpleSigning)
	if err != nil {
		return nil, err
	}
	return b, err
}
