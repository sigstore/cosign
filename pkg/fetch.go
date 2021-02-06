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
	"io/ioutil"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

type SignedPayload struct {
	Base64Signature string
	Payload         []byte
}

func FetchSignatures(ref name.Reference) ([]SignedPayload, error) {
	var idxRef name.Reference
	if tag, ok := ref.(name.Tag); ok {
		desc, err := remote.Get(tag, remote.WithAuthFromKeychain(authn.DefaultKeychain))
		if err != nil {
			return nil, err
		}
		munged := strings.ReplaceAll(desc.Digest.String(), ":", "-")
		idxRef = ref.Context().Tag(munged)
	} else if dgst, ok := ref.(name.Digest); ok {
		munged := strings.ReplaceAll(dgst.Identifier(), ":", "-")
		idxRef = ref.Context().Tag(munged)
	}

	idx, err := remote.Index(idxRef, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return nil, err
	}
	m, err := idx.IndexManifest()
	if err != nil {
		return nil, err
	}

	signatures := []SignedPayload{}
	for _, desc := range m.Manifests {
		base64sig, ok := desc.Annotations[sigkey]
		if !ok {
			continue
		}
		l, err := remote.Layer(ref.Context().Digest(desc.Digest.String()), remote.WithAuthFromKeychain(authn.DefaultKeychain))
		if err != nil {
			return nil, err
		}

		r, err := l.Compressed()
		if err != nil {
			return nil, err
		}

		payload, err := ioutil.ReadAll(r)
		if err != nil {
			return nil, err
		}
		signatures = append(signatures, SignedPayload{
			Payload:         payload,
			Base64Signature: base64sig,
		})
	}
	return signatures, nil
}
