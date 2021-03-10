/*
Copyright The Rekor Authors

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

package cosign

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
)

type SignedPayload struct {
	Base64Signature string
	Payload         []byte
}

func Munge(desc v1.Descriptor) string {
	// sha256:... -> sha256-...
	munged := strings.ReplaceAll(desc.Digest.String(), ":", "-")
	munged += ".cosign"
	return munged
}

func FetchSignatures(ref name.Reference) ([]SignedPayload, *v1.Descriptor, error) {
	var idxRef name.Reference
	targetDesc, err := remote.Get(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return nil, nil, err
	}
	idxRef = ref.Context().Tag(Munge(targetDesc.Descriptor))

	rdesc, err := remote.Get(idxRef, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		if te, ok := err.(*transport.Error); ok && te.StatusCode == http.StatusNotFound {
			return nil, nil, fmt.Errorf("manifest not found: %s", idxRef)
		}
		return nil, nil, err
	}

	if rdesc.MediaType != types.DockerManifestSchema2 {
		return nil, nil, fmt.Errorf("unsupported media type: %s", rdesc.MediaType)
	}
	descriptors, err := Descriptors(idxRef)
	if err != nil {
		return nil, nil, err
	}

	signatures := make([]SignedPayload, len(descriptors))

	g, _ := errgroup.WithContext(context.Background())

	for i, desc := range descriptors {
		i, desc := i, desc
		g.Go(func() error {
			base64sig, ok := desc.Annotations[sigkey]
			if !ok {
				return nil
			}
			l, err := remote.Layer(ref.Context().Digest(desc.Digest.String()), remote.WithAuthFromKeychain(authn.DefaultKeychain))
			if err != nil {
				return errors.Wrap(err, "remote layer")
			}

			r, err := l.Compressed()
			if err != nil {
				return errors.Wrap(err, "compressing")
			}

			payload, err := ioutil.ReadAll(r)
			if err != nil {
				return err
			}
			signatures[i] = SignedPayload{
				Payload:         payload,
				Base64Signature: base64sig,
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, nil, err
	}
	return signatures, &targetDesc.Descriptor, nil
}
