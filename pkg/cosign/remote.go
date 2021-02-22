package cosign

import (
	"bytes"
	"encoding/base64"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

func Descriptors(ref name.Reference) ([]v1.Descriptor, error) {
	img, err := remote.Image(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return nil, err
	}
	m, err := img.Manifest()
	if err != nil {
		return nil, err
	}

	return m.Layers, nil
}

func Upload(signature, payload []byte, dstTag name.Reference) error {
	l := &staticLayer{
		b:  payload,
		mt: "application/vnd.dev.cosign.simplesigning.v1+json",
	}
	base, err := remote.Image(dstTag, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		if te, ok := err.(*transport.Error); ok {
			if te.StatusCode != http.StatusNotFound {
				return te
			}
			base = empty.Image
		} else {
			return err
		}
	}

	img, err := mutate.Append(base, mutate.Addendum{
		Layer: l,
		Annotations: map[string]string{
			sigkey: base64.StdEncoding.EncodeToString(signature),
		},
	})
	if err != nil {
		return err
	}

	if err := remote.Write(dstTag, img, remote.WithAuthFromKeychain(authn.DefaultKeychain)); err != nil {
		return err
	}
	return nil
}

type staticLayer struct {
	b  []byte
	mt types.MediaType
}

func (l *staticLayer) Digest() (v1.Hash, error) {
	h, _, err := v1.SHA256(bytes.NewReader(l.b))
	return h, err
}

// DiffID returns the Hash of the uncompressed layer.
func (l *staticLayer) DiffID() (v1.Hash, error) {
	h, _, err := v1.SHA256(bytes.NewReader(l.b))
	return h, err
}

// Compressed returns an io.ReadCloser for the compressed layer contents.
func (l *staticLayer) Compressed() (io.ReadCloser, error) {
	return ioutil.NopCloser(bytes.NewReader(l.b)), nil
}

// Uncompressed returns an io.ReadCloser for the uncompressed layer contents.
func (l *staticLayer) Uncompressed() (io.ReadCloser, error) {
	return ioutil.NopCloser(bytes.NewReader(l.b)), nil
}

// Size returns the compressed size of the Layer.
func (l *staticLayer) Size() (int64, error) {
	return int64(len(l.b)), nil
}

// MediaType returns the media type of the Layer.
func (l *staticLayer) MediaType() (types.MediaType, error) {
	return l.mt, nil
}
