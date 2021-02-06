/*
Copyright The Cosign Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package pkg

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/pem"
	"fmt"
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
	"github.com/theupdateframework/go-tuf/encrypted"
)

// {
//     "critical": {
//            "identity": {
//                "docker-reference": "testing/manifest"
//            },
//            "image": {
//                "Docker-manifest-digest": "sha256:20be...fe55"
//            },
//            "type": "atomic container signature"
//     },
//     "optional": {
//            "creator": "atomic",
//            "timestamp": 1458239713
//     }
// }

const (
	pemType = "ENCRYPTED COSIGN PRIVATE KEY"
	sigkey  = "dev.ggcr.crane/signature"
)

func LoadPrivateKey(keyPath string, pass []byte) (ed25519.PrivateKey, error) {
	b, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	// Decrypt first
	p, _ := pem.Decode(b)
	if p.Type != pemType {
		return nil, fmt.Errorf("unsupported pem type: %s", p.Type)
	}

	priv, err := encrypted.Decrypt(p.Bytes, pass)
	if err != nil {
		return nil, err
	}
	return ed25519.PrivateKey(priv), nil
}

type SimpleSigning struct {
	Critical Critical
	Optional map[string]string
}

type Critical struct {
	Identity Identity
	Image    Image
	Type     string
}

type Identity struct {
	DockerReference string `json:"docker-reference"`
}

type Image struct {
	DockerManifestDigest string `json:"Docker-manifest-digest"`
}

func CreateIndex(signature, payload []byte, dstTag name.Reference) (v1.ImageIndex, error) {
	l := &staticLayer{
		b:  payload,
		mt: types.OCIContentDescriptor,
	}

	base, err := remote.Index(dstTag, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		if te, ok := err.(*transport.Error); ok {
			if te.StatusCode != http.StatusNotFound {
				return nil, te
			} else {
				base = empty.Index
			}
		} else {
			return nil, err
		}
	}

	idx := mutate.AppendManifests(base, mutate.IndexAddendum{
		Add: l,
		Descriptor: v1.Descriptor{
			Annotations: map[string]string{
				sigkey: base64.StdEncoding.EncodeToString(signature),
			},
		},
	})
	return idx, nil
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
